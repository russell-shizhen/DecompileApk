import frida
import sys

package_name = "com.arophix.decompileapk"

def native_hooking_scripts_3():
    hook_code = """
	var moduleName = "libnative-lib.so"; 
    var targetFuncAddr = '0x00004D80'; // $ nm --demangle --dynamic libnative-lib.so | grep "stringFromJNI"
    
    // see: https://www.frida.re/docs/functions/ 
    function memAddress(memBase, idaBase, idaAddr) {
        var offset = ptr(idaAddr).sub(idaBase);
        var result = ptr(memBase).add(offset);
        return result;
    }

    function idaAddress(memBase, idaBase, memAddr) {
        var offset = ptr(memAddr).sub(memBase);
        var result = ptr(idaBase).add(offset);
        return result;
    }
    
    const membase = Module.findBaseAddress(moduleName);
    console.log("[+] membase: " + membase);
    const addressOfStringFromJni = memAddress(membase, '0x0', targetFuncAddr);
    console.log("[+] addressOfStringFromJni: " + addressOfStringFromJni);
    
    Interceptor.attach(ptr(addressOfStringFromJni), {
        onEnter: function (args) {
            console.log("[++] addressOfStringFromJni: " + addressOfStringFromJni);
        },
        onLeave: function (retval) {
            console.log("ret: " + retval);
            const dstAddr = Java.vm.getEnv().newStringUtf("Frida is hooking this displayed text from Native layer by function address.");
            retval.replace(dstAddr);
        }
    });

    """
    return hook_code

##########################################################################################################
device=frida.get_usb_device()
#run package
process = device.attach(package_name)
script = process.create_script(native_hooking_scripts_3())

# Here's some message handling..
# [ It's a little bit more meaningful to read as output :-D
#   Errors get [!] and messages get [i] prefixes. ]
def on_message(message, data):
    if message['type'] == 'error':
        print("[!] " + message['stack'])
    elif message['type'] == 'send':
        print("[i] " + message['payload'])
    else:
        print(message)
script.on('message', on_message)

print('[*] Running Arophix Hook Test ...')

script.load()
sys.stdin.read()

