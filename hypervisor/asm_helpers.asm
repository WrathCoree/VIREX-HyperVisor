.code

;
; Assembly helper routines to get segment register values.
; These functions are callable from C code.
;

PUBLIC GetEs
GetEs proc
    mov ax, es
    ret
GetEs endp

PUBLIC GetCs
GetCs proc
    mov ax, cs
    ret
GetCs endp

PUBLIC GetSs
GetSs proc
    mov ax, ss
    ret
GetSs endp

PUBLIC GetDs
GetDs proc
    mov ax, ds
    ret
GetDs endp

PUBLIC GetFs
GetFs proc
    mov ax, fs
    ret
GetFs endp

PUBLIC GetGs
GetGs proc
    mov ax, gs
    ret
GetGs endp

PUBLIC GetLdtr
GetLdtr proc
    sldt ax
    ret
GetLdtr endp

PUBLIC GetTr
GetTr proc
    str ax
    ret
GetTr endp

END
