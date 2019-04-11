import frida
import sys

package_name = "com.arophix.decompileapk"

def native_hooking_scripts():
    hook_code = """
	var moduleName = "libnative-lib.so"; 
    var nativeFuncAddr = 0x00004d10; // $ nm --demangle --dynamic libnative-lib.so | grep "stringFromJNI"

    Interceptor.attach (Module.findExportByName ( moduleName, "Java_com_arophix_decompileapk_MainActivity_stringFromJNI"), {
        onEnter: function (args) {
            // send (Memory.readUtf8String (args [1]));     
            // print("[!] " +"onEnter called...")
            // this.lib = Memory.readUtf8String(args[0]);
            console.log("Java_com_arophix_decompileapk_MainActivity_stringFromJNI called with: ");
        },
        onLeave: function (retval) {
            //print("[!] " +"onLeave called...")
            //retval.replace("Frida hooking ongoing ...");
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