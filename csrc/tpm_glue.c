#include <wolftpm/tpm2_types.h>
#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_command.h>
#include <wolftpm/fwtpm/fwtpm_nv.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <string.h>

extern unsigned long long ashen_now_ms(void);

/* Masked NV backing store, implemented on the Rust side over MaskedCell so
 * the journal - which holds the hierarchy seeds - is wear-levelled. */
extern int ashen_nv_size(void);
extern int ashen_nv_read(word32 offset, byte* buf, word32 len);
extern int ashen_nv_write(word32 offset, const byte* buf, word32 len);
extern int ashen_nv_fill(word32 offset, word32 len, byte value);

static FWTPM_CTX  g_ctx;
static int        g_ready;

static int nv_read(void* halCtx, word32 offset, byte* buf, word32 size)
{
    (void)halCtx;
    if (buf == NULL || ashen_nv_read(offset, buf, size) != 0) {
        return BAD_FUNC_ARG;
    }
    return 0;
}

static int nv_write(void* halCtx, word32 offset, const byte* buf, word32 size)
{
    (void)halCtx;
    if (buf == NULL || ashen_nv_write(offset, buf, size) != 0) {
        return BAD_FUNC_ARG;
    }
    return 0;
}

static int nv_erase(void* halCtx, word32 offset, word32 size)
{
    (void)halCtx;
    if (ashen_nv_fill(offset, size, 0xFF) != 0) {
        return BAD_FUNC_ARG;
    }
    return 0;
}

static UINT64 clock_get_ms(void* halCtx)
{
    (void)halCtx;
    return (UINT64)ashen_now_ms();
}

int ashen_tpm_max_command_size(void)
{
    return FWTPM_MAX_COMMAND_SIZE;
}

int ashen_tpm_ctx_size(void)
{
    return (int)sizeof(FWTPM_CTX);
}

const char* ashen_tpm_version(void)
{
    return FWTPM_GetVersionString();
}

int ashen_tpm_init(void)
{
    FWTPM_NV_HAL hal;
    int rc;

    if (g_ready) {
        return 0;
    }

    XMEMSET(&g_ctx, 0, sizeof(g_ctx));
    if (ashen_nv_fill(0, (word32)ashen_nv_size(), 0xFF) != 0) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&hal, 0, sizeof(hal));
    hal.read       = nv_read;
    hal.write      = nv_write;
    hal.erase      = nv_erase;
    hal.ctx        = NULL;
    hal.maxSize    = (word32)ashen_nv_size();
    hal.writeAlign = 0;
    hal.appendOnly = 0;

    rc = FWTPM_NV_SetHAL(&g_ctx, &hal);
    if (rc != 0) {
        return rc;
    }

    rc = FWTPM_Clock_SetHAL(&g_ctx, clock_get_ms, NULL);
    if (rc != 0) {
        return rc;
    }

    rc = FWTPM_Init(&g_ctx);
    if (rc == 0) {
        g_ready = 1;
    }
    return rc;
}

int ashen_tpm_process(const byte* cmd, int cmdLen, byte* rsp, int* rspLen)
{
    if (!g_ready || cmd == NULL || rsp == NULL || rspLen == NULL) {
        return BAD_FUNC_ARG;
    }
    *rspLen = FWTPM_MAX_COMMAND_SIZE;
    return FWTPM_ProcessCommand(&g_ctx, cmd, cmdLen, rsp, rspLen, 0);
}

void ashen_tpm_reset_client(void)
{
    if (g_ready) {
        FWTPM_ResetCommandClient(&g_ctx);
    }
}

int ashen_tpm_shutdown(void)
{
    int rc = 0;
    if (g_ready) {
        rc = FWTPM_Cleanup(&g_ctx);
        g_ready = 0;
    }
    ashen_nv_fill(0, (word32)ashen_nv_size(), 0x00);
    wc_ForceZero(&g_ctx, sizeof(g_ctx));
    return rc;
}

int ashen_tpm_reinit(void)
{
    ashen_tpm_shutdown();
    return ashen_tpm_init();
}
