import frida
import sys

package_name = "com.arophix.decompileapk"

def native_hooking_scripts():
    hook_code = """
	var moduleName = "libnative-lib.so"; 
    var nativeFuncAddr = 0x00004d10; // $ nm --demangle --dynamic libnative-lib.so | grep "stringFromJNI"

    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            this.lib = Memory.readUtf8String(args[0]);
            console.log("dlopen called with: " + this.lib);
        },
        onLeave: function(retval) {
            if (this.lib.endsWith(moduleName)) {
                console.log("ret: " + retval);
                var baseAddr = Module.findBaseAddress(moduleName);
                Interceptor.attach(baseAddr.add(nativeFuncAddr), {
                    onEnter: function(args) {
                        console.log("[-] hook invoked");
                        console.log(JSON.stringify({
                            a1: args[1].toInt32(),
                            a2: Memory.readUtf8String(Memory.readPointer(args[2])),
                            a3: Boolean(args[3])
                        }, null, '\t'));
                    }
                });
            }
        }
    });

    
    """
    return hook_code

device=frida.get_usb_device()
#run package
process = device.attach(package_name)
script = process.create_script(native_hooking_scripts())

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

print('[*] Running IDP Hook Test ...')

script.load()
sys.stdin.read()