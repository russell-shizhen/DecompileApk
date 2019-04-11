import frida
import sys

package_name = "com.arophix.decompileapk"

# Hook the JNI function by function address -- Not yet working ...
def native_hooking_scripts_3_2():
    hook_code = """
	var moduleName = "libnative-lib.so"; 
    var nativeFuncAddr = '0x00004D80'; // $ nm --demangle --dynamic libnative-lib.so | grep "stringFromJNI"
    
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

    var IDABASE = '0x000000000';
    var BASE = Module.findBaseAddress('libnative-lib.so');

    Interceptor.attach(memAddress(BASE, IDABASE, nativeFuncAddr), {
        onEnter: function(args){
            console.log("INSIDE PROVISIONING_CONT FUNCTION");
            console.log(ptr(args[2].toInt32()));
        },
        onLeave: function(retval){
            console.log("EXITING PROVISIONING_CONT");
            console.log(ptr(retval.toInt32()));
            //console.log(Memory.readUtf8String(retval));
        }
    });

    """
    return hook_code


##########################################################################################################
device=frida.get_usb_device()
#run package
process = device.attach(package_name)
script = process.create_script(native_hooking_scripts_3_2())

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

print('[*] Running Hook Test ...')

script.load()
sys.stdin.read()
