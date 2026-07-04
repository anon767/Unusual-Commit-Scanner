rule threat_runtime_obfuscation_base64exec
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects base64 decoding followed by code execution"
        identifies = "threat.runtime.obfuscation.base64exec"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "medium"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go,*.rb,*.gemspec,*.cpp,*.cc,*.cxx,*.h,*.hpp,*.cs,*.rs"

    strings:
        // Python - base64 decode + exec/eval
        $py_b64decode = /\bbase64\s*\.\s*b64decode\s*\(/ nocase
        $py_b64decode_alt = /\bbase64\s*\.\s*decodebytes\s*\(/ nocase
        $py_b64decode_std = /\bbase64\s*\.\s*standard_b64decode\s*\(/ nocase
        // bare exec(/eval( builtins, not method calls like model.eval()
        $py_exec = /[^.\w]exec\s*\(/ nocase
        $py_eval = /[^.\w]eval\s*\(/ nocase

        // JavaScript/Node.js - base64 decode patterns
        $js_atob = /\batob\s*\(/ nocase
        // Buffer.from with explicit base64 encoding (not just any Buffer.from)
        $js_buffer_b64 = /Buffer\s*\.\s*from\s*\([^)]*['"]base64['"]/ nocase
        $js_eval = /\beval\s*\(/ nocase
        $js_function = /\bnew\s+Function\s*\(/ nocase

        // Go - base64 decode + exec
        $go_b64decode = /\bbase64\s*\.\s*StdEncoding\s*\.\s*DecodeString\s*\(/ nocase
        $go_b64decode_alt = /\bbase64\s*\.\s*URLEncoding\s*\.\s*DecodeString\s*\(/ nocase
        $go_exec = /\bexec\s*\.\s*Command\s*\(/ nocase

        // Ruby - base64 decode
        $rb_b64decode = /\bBase64\s*\.\s*decode64\s*\(/ nocase
        $rb_b64decode_strict = /\bBase64\s*\.\s*strict_decode64\s*\(/ nocase
        $rb_b64decode_url = /\bBase64\s*\.\s*urlsafe_decode64\s*\(/ nocase
        $rb_unpack_m = /\.\s*unpack\s*\(\s*['"]m0?['"]/ nocase

        // Ruby - eval methods
        $rb_eval = /\beval\s*\(/ nocase
        $rb_instance_eval = /\binstance_eval\s*\(/ nocase

        // C++ - no stdlib base64, so match common third-party decode calls
        // (OpenSSL BIO, Boost.Beast/Boost.Archive) + a process-exec sink.
        // Manual byte-shuffling decode loops are deliberately not matched --
        // too generic, would false-positive on any bit-twiddling code.
        $cpp_openssl_b64 = /BIO_f_base64\s*\(/ nocase
        $cpp_boost_b64 = /boost\s*::\s*(beast\s*::\s*detail\s*::\s*base64|archive\s*::\s*iterators\s*::\s*binary_from_base64)/ nocase
        $cpp_system = /[^.\w](system|popen)\s*\(/ nocase
        $cpp_exec_family = /\bexecl?p?e?\s*\(/ nocase

        // C# / .NET - Convert.FromBase64String + reflection/dynamic execution
        $cs_b64decode = /Convert\s*\.\s*FromBase64String\s*\(/ nocase
        $cs_assembly_load = /Assembly\s*\.\s*Load\s*\(/ nocase
        $cs_dynamic_method = /\bDynamicMethod\s*\(/ nocase
        $cs_csscript_eval = /CSharpScript\s*\.\s*(Run|Eval|EvaluateAsync|RunAsync)\s*\(/ nocase

        // Rust - base64 crate decode + process spawn
        $rs_b64decode = /base64\s*::\s*(decode|engine\s*::\s*general_purpose)/ nocase
        $rs_command_new = /Command\s*::\s*new\s*\(/ nocase
        $rs_command_spawn = /\.\s*spawn\s*\(\s*\)/ nocase

    condition:
        (any of ($py_b64decode*) and any of ($py_exec, $py_eval)) or
        (($js_atob or $js_buffer_b64) and ($js_eval or $js_function)) or
        (any of ($go_b64decode*) and $go_exec) or
        (any of ($rb_b64decode*, $rb_unpack_m) and any of ($rb_eval, $rb_instance_eval)) or
        (any of ($cpp_openssl_b64, $cpp_boost_b64) and any of ($cpp_system, $cpp_exec_family)) or
        ($cs_b64decode and any of ($cs_assembly_load, $cs_dynamic_method, $cs_csscript_eval)) or
        ($rs_b64decode and $rs_command_new and $rs_command_spawn)
}
