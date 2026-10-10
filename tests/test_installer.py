import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('installer',ROOT/'installer/install.py')
installer=importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def args(self,*values): return installer.validate(installer.parser().parse_args(values))

    def test_safe_defaults_and_matching_paths(self):
        args=self.args()
        self.assertEqual(args.ip_map,{})
        conf=installer.configs(args)
        self.assertIn('127.0.0.1:80',conf['/etc/nginx/conf.d/malsonsa.conf'])
        self.assertIn('SOC_DB_PATH=/var/lib/soc-siem/siem.db',conf['/etc/malsonsa/siem.env'])
        self.assertIn('SOC_RSYSLOG_LOG=/var/log/soc/all-rsyslog.log',conf['/etc/malsonsa/siem.env'])
        self.assertIn('ReadWritePaths=/var/lib/soc-siem',conf['/etc/systemd/system/soc-siem.service'])
        self.assertIn('ruleset="MalsonsaIngress"',conf['/etc/rsyslog.d/10-malsonsa.conf'])
        self.assertIn('template="MalsonsaFormat"',conf['/etc/rsyslog.d/10-malsonsa.conf'])

    def test_external_binding_needs_trusted_sources(self):
        with self.assertRaises(ValueError): self.args('--bind','0.0.0.0')
        args=self.args('--bind','0.0.0.0','--allow-source','192.0.2.0/24','--hostname','siem.example.test')
        conf=installer.configs(args)
        self.assertIn('allow 192.0.2.0/24;',conf['/etc/nginx/conf.d/malsonsa.conf'])
        self.assertIn('deny all;',conf['/etc/nginx/conf.d/malsonsa.conf'])
        self.assertIn('$AllowedSender TCP, 127.0.0.1, [::1]/128, 192.0.2.0/24',conf['/etc/rsyslog.d/10-malsonsa.conf'])

    def test_ipv6_sender_syntax(self):
        conf=installer.configs(self.args('--allow-source','2001:db8::/32'))
        self.assertIn('[2001:db8::]/32',conf['/etc/rsyslog.d/10-malsonsa.conf'])
        with self.assertRaises(ValueError): self.args('--allow-source','::/0')

    def test_invalid_configuration_rejected(self):
        for values in [('--hostname','x;root /tmp;'),('--bind','not-ip'),('--web-port','8000'),('--ip-map','[]'),('--ip-map','{"x":"y"}')]:
            with self.subTest(values=values),self.assertRaises(ValueError): self.args(*values)

    def test_render_does_not_escape_output_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            installer.main(['--render-dir',temp])
            self.assertTrue((Path(temp)/'etc/nginx/conf.d/malsonsa.conf').exists())
            self.assertTrue((Path(temp)/'usr/share/nginx/html/soc/frontend/site-config.js').exists())


if __name__=='__main__': unittest.main()
