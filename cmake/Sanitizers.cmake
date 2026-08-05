# Sanitizer wiring.
#
# ThreadSanitizer is mutually exclusive with AddressSanitizer, so a
# configuration that requests both is rejected at configure time rather than
# producing a confusing link error.

if(PQTLS_ENABLE_TSAN AND (PQTLS_ENABLE_ASAN OR PQTLS_ENABLE_UBSAN))
    message(FATAL_ERROR
        "PQTLS_ENABLE_TSAN cannot be combined with ASan/UBSan. "
        "Configure a separate build directory for the ThreadSanitizer build.")
endif()

function(pqtls_enable_sanitizers target)
    if(MSVC)
        if(PQTLS_ENABLE_ASAN)
            target_compile_options(${target} PRIVATE /fsanitize=address)
        endif()
        return()
    endif()

    set(_sanitizers "")
    if(PQTLS_ENABLE_ASAN)
        list(APPEND _sanitizers address)
    endif()
    if(PQTLS_ENABLE_UBSAN)
        list(APPEND _sanitizers undefined)
    endif()
    if(PQTLS_ENABLE_TSAN)
        list(APPEND _sanitizers thread)
    endif()

    if(_sanitizers)
        list(JOIN _sanitizers "," _sanitizer_arg)
        target_compile_options(${target} PRIVATE
            -fsanitize=${_sanitizer_arg}
            -fno-omit-frame-pointer
            -g)
        target_link_options(${target} PRIVATE -fsanitize=${_sanitizer_arg})

        if(PQTLS_ENABLE_UBSAN)
            # Make UB an immediate, loud failure rather than a log line that CI
            # will happily ignore.
            target_compile_options(${target} PRIVATE -fno-sanitize-recover=undefined)
        endif()
    endif()
endfunction()
