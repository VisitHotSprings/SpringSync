# Pinned, checksum-verified third-party pieces for the Windows host (SPEC 11.5, 9.8).
# Every file is the official, unmodified download; install.ps1 refuses anything whose SHA-256 differs.
# Keep in sync with deploy/install.sh (rclone/Caddy/Go pins) and requirements-windows.lock (wheels).
@{
    Python = @{
        Version  = '3.13.17'
        File     = 'python-3.13.17-embed-amd64.zip'
        Source   = 'https://www.python.org/ftp/python/3.13.17/python-3.13.17-embed-amd64.zip'
        Sha256   = '9e35319bffedab8b36ad44d8f377cb4f1733bcec257a0b6d04d94f01486ddb38'
        PthFile  = 'python313._pth'
    }
    Pip = @{
        Version  = '26.2.2'
        File     = 'pip-26.2.2-py3-none-any.whl'
        Source   = 'https://pypi.org/project/pip/26.2.2/'
        Sha256   = 'fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70'
    }
    Rclone = @{
        Version   = 'v1.75.2'
        File      = 'rclone-v1.75.2-windows-amd64.zip'
        Source    = 'https://downloads.rclone.org/v1.75.2/rclone-v1.75.2-windows-amd64.zip'
        Sha256    = '8a9db2bad1dc79a65b3348fd857069598e2aab7cf4d118b77b1df23055aff818'
        ExeSha256 = '41eab3e118d264920b62c3327966c5ece0dc4dd715ee617d9e30450d8ead95a4'
    }
    Caddy = @{
        # Not shipped: built with xcaddy by deploy/windows/build-caddy-windows.sh (same pins as install.sh).
        Version          = 'v2.11.7'
        DnsModule        = 'github.com/caddy-dns/googleclouddns'
        DnsModuleVersion = 'v1.1.0'
        DnsModuleH1      = 'h1:SDxKxFh7d5Jq2/JPnu9Jv8ErOIdfXmK+Oad0qVzQi80='
        GoVersion        = '1.27.3'
        XcaddyVersion    = 'v0.4.7'
    }
}
