rule threat_runtime_dynamic_loader
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects dynamic code loading: downloading and importing/executing code at runtime"
        identifies = "threat.runtime.obfuscation"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "high"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.cpp,*.cc,*.cxx,*.h,*.hpp,*.cs,*.rs"

    strings:
        // Dynamic import mechanisms
        $importlib_import = /importlib\.import_module\s*\(/ nocase
        $importlib_util = /importlib\.util\.spec_from_/ nocase
        $builtins_import = /__import__\s*\(/ nocase

        // getattr for dynamic function resolution
        $getattr_call = /getattr\s*\(\s*\w+\s*,/ nocase

        // Network download via an actual fetch call, not a bare urllib import
        $urllib_dl = /urllib\.\w*request\w*\.(urlopen|urlretrieve)\s*\(/ nocase
        $requests_get = /requests\.get\s*\(/ nocase

        // base64 decode (for obfuscated module names/URLs)
        $b64_decode = /base64\.\w*decode/ nocase
        $b64_b64decode = /b64decode\s*\(/ nocase

        // Execution sink: bare exec(/eval(, not method calls. Required alongside
        // import+download, which co-occur in many benign plugin loaders.
        $exec_sink = /[^.\w]exec\s*\(/ nocase
        $eval_sink = /[^.\w]eval\s*\(/ nocase

        // C++ - runtime dynamic library loading + symbol resolution
        $cpp_dlopen = /\bdlopen\s*\(/ nocase
        $cpp_dlsym = /\bdlsym\s*\(/ nocase
        $cpp_loadlibrary = /\bLoadLibrary[AW]?\s*\(/ nocase
        $cpp_getprocaddress = /\bGetProcAddress\s*\(/ nocase

        // C# / .NET - reflection-based assembly loading from a byte array
        // (downloaded/decoded in memory) + invoking a resolved method
        $cs_assembly_load = /Assembly\s*\.\s*(Load|LoadFrom|LoadFile)\s*\(/ nocase
        $cs_activator = /Activator\s*\.\s*CreateInstance\s*\(/ nocase
        $cs_invoke = /\.\s*Invoke\s*\(/ nocase
        $cs_webclient = /\bWebClient\s*\(\s*\)\s*\.\s*DownloadData/ nocase
        $cs_httpclient_getbytes = /HttpClient\s*\(\s*\)[\s\S]{0,80}GetByteArrayAsync/ nocase

        // Rust - dynamic library loading (libloading crate) + downloaded bytes
        $rs_libloading = /libloading\s*::\s*Library\s*::\s*new\s*\(/ nocase
        $rs_get_symbol = /\.\s*get\s*::\s*<[^>]*>\s*\(/ nocase
        $rs_reqwest_bytes = /reqwest\s*::\s*(get|blocking\s*::\s*get)\s*\(/ nocase

    condition:
        // Dynamic import + network download + execution of the payload
        (any of ($importlib_*, $builtins_import) and any of ($urllib_*, $requests_get) and any of ($exec_sink, $eval_sink)) or
        // Dynamic import + getattr + base64 (obfuscated dynamic loading)
        (any of ($importlib_*, $builtins_import) and $getattr_call and any of ($b64_*)) or
        // C++ - resolve a library handle then look up a symbol dynamically
        ((any of ($cpp_dlopen, $cpp_loadlibrary)) and any of ($cpp_dlsym, $cpp_getprocaddress)) or
        // C# - load an assembly (often from downloaded/decoded bytes) then invoke it
        (any of ($cs_assembly_load) and any of ($cs_activator, $cs_invoke) and any of ($cs_webclient, $cs_httpclient_getbytes)) or
        // Rust - dynamically load a native library and resolve a symbol from it,
        // combined with a network fetch (downloaded payload driving the load)
        ($rs_libloading and $rs_get_symbol and $rs_reqwest_bytes)
}
