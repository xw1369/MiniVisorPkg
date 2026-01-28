@echo off
REM MiniVisor Package Build Verification Script
REM 验证 MiniVisor 包的构建配置和依赖关系

echo MiniVisor 包构建验证开始...
echo ==================================================

echo.
echo 1. 检查包文件结构:
echo --------------------------------------------------

if exist "MiniVisorPkg.dec" (
    echo ✓ Package Declaration: MiniVisorPkg.dec
) else (
    echo ✗ Package Declaration: MiniVisorPkg.dec [NOT FOUND]
)

if exist "MiniVisorPkg.dsc" (
    echo ✓ Package Description: MiniVisorPkg.dsc
) else (
    echo ✗ Package Description: MiniVisorPkg.dsc [NOT FOUND]
)

if exist "Drivers\MiniVisorDxe\MiniVisorDxe.inf" (
    echo ✓ Main Driver INF: Drivers\MiniVisorDxe\MiniVisorDxe.inf
) else (
    echo ✗ Main Driver INF: Drivers\MiniVisorDxe\MiniVisorDxe.inf [NOT FOUND]
)



if exist "Tools\HardwareCollector\HardwareCollector.inf" (
    echo ✓ Hardware Collector INF: Tools\HardwareCollector\HardwareCollector.inf
) else (
    echo ✗ Hardware Collector INF: Tools\HardwareCollector\HardwareCollector.inf [NOT FOUND]
)

echo.
echo 2. 检查源文件:
echo --------------------------------------------------

if exist "Drivers\MiniVisorDxe\MiniVisorDxe.c" (
    echo ✓ MiniVisorDxe.c
) else (
    echo ✗ MiniVisorDxe.c [NOT FOUND]
)

if exist "Drivers\MiniVisorDxe\VmxAsm.nasm" (
    echo ✓ VmxAsm.nasm
) else (
    echo ✗ VmxAsm.nasm [NOT FOUND]
)



if exist "Tools\HardwareCollector\HardwareCollector.c" (
    echo ✓ HardwareCollector.c
) else (
    echo ✗ HardwareCollector.c [NOT FOUND]
)

echo.
echo 3. 检查头文件:
echo --------------------------------------------------

if exist "Drivers\MiniVisorDxe\VmxDefs.h" (
    echo ✓ VmxDefs.h
) else (
    echo ✗ VmxDefs.h [NOT FOUND]
)

if exist "Drivers\MiniVisorDxe\VmxStructs.h" (
    echo ✓ VmxStructs.h
) else (
    echo ✗ VmxStructs.h [NOT FOUND]
)

echo.
echo ==================================================
echo 验证完成! 
echo Verification completed!
echo ==================================================

pause
