"""Agent-scoped declarative detection rules. No executable expressions or regex."""
import json
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

FIELDS = {'message', 'program', 'event', 'src_ip', 'dst_ip', 'user', 'mitre'}
GROUPS = {'src_ip', 'dst_ip', 'user', 'program', 'agent'}


def validate(data):
    if not isinstance(data, dict): raise ValueError('룰은 JSON 객체여야 합니다.')
    result = {}
    for key, size in [('name', 100), ('attack', 120), ('reason', 1000)]:
        value = data.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > size:
            raise ValueError(f'{key}: 1~{size}자 입력이 필요합니다.')
        result[key] = value.strip()
    for key, default, low, high in [('host_id', None, 1, 2147483647), ('points', None, 1, 200), ('min_hits', 1, 1, 10000), ('window_seconds', 300, 1, 86400)]:
        value = data.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'{key}: {low}~{high} 범위의 정수가 필요합니다.')
        result[key] = value
    result['enabled'] = data.get('enabled', True)
    if type(result['enabled']) not in (bool, int) or result['enabled'] not in (True, False, 0, 1):
        raise ValueError('enabled는 true 또는 false여야 합니다.')
    result['enabled'] = int(result['enabled'])
    result['match_mode'] = data.get('match_mode', 'all')
    result['group_by'] = data.get('group_by', 'src_ip')
    if result['match_mode'] not in ('all', 'any') or result['group_by'] not in GROUPS:
        raise ValueError('조건 조합 또는 반복 묶음 기준이 잘못되었습니다.')
    conditions = data.get('conditions')
    if not isinstance(conditions, list) or not 1 <= len(conditions) <= 8:
        raise ValueError('조건은 1~8개 필요합니다.')
    result['conditions'] = []
    for condition in conditions:
        if not isinstance(condition, dict): raise ValueError('조건 형식이 잘못되었습니다.')
        field, operator, value = (condition.get(k) for k in ('field', 'operator', 'value'))
        if field not in FIELDS or operator not in ('contains', 'equals'):
            raise ValueError('허용되지 않은 필드 또는 비교 방식입니다.')
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError('조건 값은 1~256자 필요합니다.')
        result['conditions'].append({'field': field, 'operator': operator, 'value': value.strip()})
    return result


def public(row):
    result = dict(row)
    result['conditions'] = json.loads(result['conditions'])
    return result


def condition_match(condition, event):
    actual = str(event.get(condition['field']) or '').casefold()
    expected = condition['value'].casefold()
    return expected in actual if condition['operator'] == 'contains' else expected == actual


def evaluate(connection, rule, event):
    if not rule['enabled'] or event.get('host_ip') != rule['host_ip']: return None
    matched = [condition_match(condition, event) for condition in rule['conditions']]
    if not (all(matched) if rule['match_mode'] == 'all' else any(matched)): return None
    hits = 1
    if rule['min_hits'] > 1:
        group = rule['group_by']
        if group != 'agent' and not event.get(group): return None
        try:
            end = datetime.fromisoformat(str(event.get('time', '')).replace('Z', '+00:00'))
            if end.tzinfo is None: end = end.replace(tzinfo=timezone.utc)
        except ValueError: return None
        start = end - timedelta(seconds=rule['window_seconds'])
        sql = 'SELECT COUNT(*) FROM events WHERE host_ip=? AND julianday(time)>=julianday(?) AND julianday(time)<=julianday(?)'
        params = [rule['host_ip'], start.isoformat(), end.isoformat()]
        # Only count events at or before this stored event when timestamps tie.
        if event.get('id'):
            sql += ' AND id<=?'; params.append(event['id'])
        if group != 'agent':
            sql += f' AND {group}=?'; params.append(event[group])
        clauses = []
        for condition in rule['conditions']:
            field = condition['field']  # validated allowlist, never user SQL
            clauses.append(f"instr(soc_casefold(COALESCE({field},'')),?)>0" if condition['operator'] == 'contains' else f"soc_casefold(COALESCE({field},''))=?")
            params.append(condition['value'].casefold())
        sql += ' AND (' + (' AND ' if rule['match_mode'] == 'all' else ' OR ').join(clauses) + ')'
        hits = connection.execute(sql, params).fetchone()[0]
        if hits < rule['min_hits']: return None
    evidence = [{'field': condition['field'], 'operator': condition['operator'], 'expected': condition['value'], 'actual': str(event.get(condition['field']) or '')[:500]} for condition, ok in zip(rule['conditions'], matched) if ok]
    return {'rule_id': rule.get('id'), 'name': rule['name'], 'attack': rule['attack'], 'points': rule['points'], 'reason': rule['reason'], 'evidence': evidence, 'hits': hits, 'min_hits': rule['min_hits'], 'window_seconds': rule['window_seconds'], 'group_by': rule['group_by']}


def register_rules(app, db, now_iso):
    c = db()
    try:
        c.execute('''CREATE TABLE IF NOT EXISTS detection_rules(
            id INTEGER PRIMARY KEY AUTOINCREMENT, host_id INTEGER NOT NULL,
            name TEXT NOT NULL, attack TEXT NOT NULL, reason TEXT NOT NULL,
            points INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            conditions TEXT NOT NULL, match_mode TEXT NOT NULL,
            min_hits INTEGER NOT NULL, window_seconds INTEGER NOT NULL,
            group_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_detection_rules_host ON detection_rules(host_id,enabled)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_events_rule_time ON events(host_ip,time)')
        c.commit()
    finally: c.close()

    def load(c):
        return [public(r) for r in c.execute('''SELECT r.*, h.ip host_ip, h.name host_name FROM detection_rules r
            JOIN monitored_hosts h ON h.id=r.host_id WHERE r.enabled=1 AND h.enabled=1 ORDER BY r.id''')]

    def annotate(events):
        c = db()
        try:
            rules = load(c)
            by_host = {}
            for rule in rules: by_host.setdefault(rule['host_ip'], []).append(rule)
            for event in events:
                detections = [found for rule in by_host.get(event.get('host_ip'), []) for found in [evaluate(c, rule, event)] if found]
                event['detections'] = detections
                event['detection_score'] = sum(item['points'] for item in detections)
                event['detection_basis'] = 'current_rules'
            return events
        finally: c.close()

    @app.get('/api/rules')
    def list_rules():
        c = db()
        try:
            return jsonify({'rules': [public(r) for r in c.execute('''SELECT r.*,h.ip host_ip,h.name host_name,
                h.enabled host_enabled FROM detection_rules r LEFT JOIN monitored_hosts h ON h.id=r.host_id ORDER BY r.id DESC''')]})
        finally: c.close()

    def save(rule_id=None):
        c = db()
        try:
            data = request.get_json(silent=True)
            if rule_id is not None:
                old = c.execute('SELECT * FROM detection_rules WHERE id=?', (rule_id,)).fetchone()
                if not old: return jsonify({'error': '룰을 찾을 수 없습니다.'}), 404
                if not isinstance(data, dict): raise ValueError('JSON 객체가 필요합니다.')
                data = dict(public(old), **data)
            rule = validate(data)
            host = c.execute('SELECT id FROM monitored_hosts WHERE id=?', (rule['host_id'],)).fetchone()
            if not host: raise ValueError('등록된 에이전트를 선택하세요.')
            if rule_id is None and c.execute('SELECT COUNT(*) FROM detection_rules WHERE host_id=?', (rule['host_id'],)).fetchone()[0] >= 100:
                raise ValueError('에이전트당 최대 100개 룰을 지원합니다.')
            fields = list(rule)
            values = [json.dumps(rule[key], ensure_ascii=False) if key == 'conditions' else rule[key] for key in fields]
            if rule_id is None:
                fields += ['created_at', 'updated_at']; values += [now_iso(), now_iso()]
                cursor = c.execute('INSERT INTO detection_rules('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')', values)
                rule_id = cursor.lastrowid
            else:
                fields += ['updated_at']; values += [now_iso()]
                c.execute('UPDATE detection_rules SET '+','.join(key+'=?' for key in fields)+' WHERE id=?', values+[rule_id])
            c.commit()
            return jsonify({'ok': True, 'id': rule_id}), 201 if request.method == 'POST' else 200
        except (ValueError, TypeError) as exc: return jsonify({'error': str(exc)}), 400
        finally: c.close()

    app.add_url_rule('/api/rules', 'create_rule', save, methods=['POST'])
    app.add_url_rule('/api/rules/<int:rule_id>', 'update_rule', save, methods=['PATCH'])

    @app.delete('/api/rules/<int:rule_id>')
    def delete_rule(rule_id):
        c = db()
        try:
            cursor = c.execute('DELETE FROM detection_rules WHERE id=?', (rule_id,)); c.commit()
            return (jsonify({'ok': True}), 200) if cursor.rowcount else (jsonify({'error': '룰을 찾을 수 없습니다.'}), 404)
        finally: c.close()

    @app.post('/api/rules/preview')
    def preview_rule():
        c = db()
        try:
            data = request.get_json(silent=True)
            if not isinstance(data, dict): raise ValueError('JSON 객체가 필요합니다.')
            rule = validate(data.get('rule'))
            host = c.execute('SELECT ip,enabled FROM monitored_hosts WHERE id=?', (rule['host_id'],)).fetchone()
            if not host: raise ValueError('등록된 에이전트를 선택하세요.')
            rule['host_ip'] = host['ip']
            if not host['enabled']: rule['enabled'] = 0
            event_id = data.get('event_id')
            if type(event_id) is not int: raise ValueError('테스트할 수집 로그의 ID를 지정하세요.')
            event = c.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
            if not event: return jsonify({'error': '로그를 찾을 수 없습니다.'}), 404
            result = evaluate(c, rule, dict(event))
            return jsonify({'matched': bool(result), 'detection': result, 'note': '저장 전 룰을 해당 로그와 이전 수집 로그에 적용한 결과입니다. 에이전트·조건·반복 횟수·활성 상태를 모두 확인합니다.'})
        except (ValueError, TypeError) as exc: return jsonify({'error': str(exc)}), 400
        finally: c.close()

    return annotate
