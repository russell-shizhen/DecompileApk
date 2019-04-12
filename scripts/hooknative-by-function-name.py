import frida
import sys

package_name = "com.arophix.decompileapk"

def native_hooking_scripts_2():
    hook_code = """
        var moduleName = "libnative-lib.so"; 
        var targetFuncAddr = 0x00004d80; // $ nm --demangle --dynamic libnative-lib.so | grep "stringFromJNI"

        
        Interceptor.attach (Module.findExportByName (moduleName, "Java_com_arophix_decompileapk_MainActivity_stringFromJNI"), {
            onEnter: function (args) {
                // send (Memory.readUtf8String (args [1]));     
                // print("[!] " +"onEnter called...")
                // this.lib = Memory.readUtf8String(args[0]);
                console.log("Java_com_arophix_decompileapk_MainActivity_stringFromJNI called with: ");
            },
            // Change the returned String
            onLeave: function (retval) {
                console.log("ret: " + retval);
                const dstAddr = Java.vm.getEnv().newStringUtf("Frida is hooking this displayed text from Native layer by function name.");
                retval.replace(dstAddr);
            }
        });
    """
    return hook_code

##########################################################################################################
device=frida.get_usb_device()
#run package
process = device.attach(package_name)
script = process.create_script(native_hooking_scripts_2())

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

