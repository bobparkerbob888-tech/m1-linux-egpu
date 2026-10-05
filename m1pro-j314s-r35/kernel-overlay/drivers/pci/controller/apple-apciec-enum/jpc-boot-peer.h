#ifndef JPC_BOOT_PEER_H
#define JPC_BOOT_PEER_H
#include "j314s-boot-admission.h"
/* Exact masks3/5 contain one peer; mask7 is deliberately unsupported. */
static unsigned jpc_boot_peer_controller(void)
{
 unsigned mask=j314s_boot_admission_mask(saved_command_line);
 return mask==2||mask==3?1:mask==4||mask==5?2:0;
}
#endif
