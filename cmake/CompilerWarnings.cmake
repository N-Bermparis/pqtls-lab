# Centralised warning configuration.
#
# Rationale: warnings are the cheapest static analysis available. The list is
# applied to every first-party target. It is deliberately NOT applied to
# fetched third-party dependencies, whose warnings we cannot fix and which
# would otherwise force us to weaken the set.

function(pqtls_set_warnings target)
    if(MSVC)
        set(_warnings
            /W4
            /permissive-
            /w14242  # conversion, possible loss of data
            /w14254  # larger bit field assigned to smaller
            /w14263  # member function does not override any base member
            /w14265  # class has virtual functions but non-virtual destructor
            /w14287  # unsigned/negative constant mismatch
            /w14296  # expression is always false
            /w14311  # pointer truncation
            /w14545 /w14546 /w14547 /w14549 /w14555
            /w14619  # unknown pragma warning
            /w14640  # thread-unsafe static member initialisation
            /w14826  # sign-extending conversion
            /w14905 /w14906
            /w14928)
        if(PQTLS_ENABLE_WERROR)
            list(APPEND _warnings /WX)
        endif()
    else()
        set(_warnings
            -Wall
            -Wextra
            -Wpedantic
            -Wshadow
            -Wnon-virtual-dtor
            -Wold-style-cast          # enforces the "no C-style casts" rule
            -Wcast-align
            -Wcast-qual
            -Wunused
            -Woverloaded-virtual
            -Wconversion
            -Wsign-conversion
            -Wdouble-promotion
            -Wformat=2
            -Wimplicit-fallthrough
            -Wnull-dereference
            -Wextra-semi)

        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
            list(APPEND _warnings
                -Wmisleading-indentation
                -Wduplicated-cond
                -Wduplicated-branches
                -Wlogical-op
                -Wuseless-cast)
        endif()

        if(PQTLS_ENABLE_WERROR)
            list(APPEND _warnings -Werror)
        endif()
    endif()

    target_compile_options(${target} PRIVATE ${_warnings})
endfunction()
