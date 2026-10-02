# Per-repo fleet start config for copy-fail-mcp
# Edit ports/backend target here - start.ps1 is fleet-standard.
@{
    Name         = 'copy-fail-mcp'
    BackendPort  = 10955
    FrontendPort = 10954
    HealthPath   = '/health'
    WebRoot      = 'webapp'
    Backend = @{
        Kind       = 'module-serve'
        Module     = 'copy_fail_mcp'
        ServeArgs  = @('serve', '--http', '--port', '10955')
        SyncExtras = @('dev')
    }
    Frontend = @{
        Kind           = 'vite-npm'
        PackageManager = 'npm'
        PortEnvVar     = 'VITE_PORT'
        ApiTargetEnv   = 'VITE_API_TARGET'
    }
}
