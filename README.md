# Kernel-Native Forensic Evasion (Minifilter Suite)

**Author:** opsecblueberry
**License:** GPL-3.0

## State of the Evasion Scene

Let's address the current scene: 99% of the "forensic bypasses" sold on Discord are absolute garbage. 
They rely on pasting decade-old vulnerable drivers (like `capcom.sys` or `gdrv.sys`), 
clearing the entire `Prefetch` folder, or wiping the `Amcache` via batch scripts. 

These are not bypasses. They are massive red flags. 
Any decent forensic analyst or EDR will flag an empty `Amcache` or a wiped `Prefetch` folder instantly. 
The absence of logs is the loudest log you can leave behind. If your "bypass" relies on post-execution cleaning, you are doing it wrong.


## The Real Architecture

This project demonstrates how actual evasion works at Ring-0. 
It leverages native Windows Kernel architecture (`FltMgr.sys`) to manipulate the File System and Registry *before* telemetry or forensic artifacts 
can even be generated. It does not clean logs; it prevents reality from being recorded.


### Deep-Dive Capabilities:

**Prefetch Spoofing (`IRP_MJ_CREATE`):** Instead of deleting `.pf` files (which triggers alerts), 
the Minifilter intercepts the exact `IRP_MJ_CREATE` request meant for targeted executables and returns `STATUS_ACCESS_DENIED` to the OS tracer. 
The system runs normally, but the target leaves no Prefetch trace.

**USN Journal Bypassing (`IRP_MJ_FILE_SYSTEM_CONTROL`): 
Most forensic tools (like FTK Imager) rely on the `$J` (USN Journal) to rebuild file history. 
This filter intercepts `FSCTL` queries to the Journal and surgically removes targeted file entries on-the-fly. The MFT is bypassed entirely.

**Amcache / Registry Evasion (`CmRegisterCallbackEx`):
No more deleting registry hives. The driver uses `RegNtPostEnumerateKey` with `STATUS_CALLBACK_BYPASS` to dynamically hide specific Amcache entries.
If RegEdit or an EDR tries to enumerate the keys, the Kernel lies to them and says the key doesn't exist.


**Process Obfuscation (`ObRegisterCallbacks`): 
Strips `PROCESS_VM_READ` and `PROCESS_VM_WRITE` dynamically during handle creation. 
Protects the target process memory without using noisy SSDT hooks.


## Notice

Released for advanced Windows Internals research. No pre-compiled binaries. No instructions on bypassing DSE.

*If you copy-paste this into your 20$ Discord P2C without understanding how an IRP hook works, you are just proving my point.*



