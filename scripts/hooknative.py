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
                
            }
        }
    });

    // Hook the JNI function by function name
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

    // see: https://www.frida.re/docs/functions/
    Module.enumerateSymbolsSync(moduleName).forEach(function(symbol){
        switch (symbol.name) {
            case "Java_com_arophix_decompileapk_MainActivity_stringFromJNI":
                /*
                    $ c++filt "_ZN3art3JNI21RegisterNativeMethodsEP7_JNIEnvP7_jclassPK15JNINativeMethodib"
                    art::JNI::RegisterNativeMethods(_JNIEnv*, _jclass*, JNINativeMethod const*, int, bool)
                */
                var RegisterNativeMethodsPtr = symbol.address;
                console.log("RegisterNativeMethods is at " + RegisterNativeMethodsPtr);
                Interceptor.attach(RegisterNativeMethodsPtr, {
                    onEnter: function(args) {
                        console.log("[-] hook invoked");
                        console.log("RegisterNativeMethodsPtr:" + RegisterNativeMethodsPtr);
                        console.log("Java_com_arophix_decompileapk_MainActivity_stringFromJNI called with address.");
                    },
                    onLeave: function (retval) {
                        console.log("ret: " + retval);
                        const dstAddr = Java.vm.getEnv().newStringUtf("Frida is hooking this displayed text from Native layer by address.");
                        retval.replace(dstAddr);
                    }
                });
                break;
            case "_ZN3art3JNI9FindClassEP7_JNIEnvPKc": // art::JNI::FindClass
                Interceptor.attach(symbol.address, {
                    onEnter: function(args) {
                        if (args[1] != null) {
                            jclassAddress2NameMap[args[0]] = Memory.readCString(args[1]);
                        }
                    },
                    onLeave: function (ignoredReturnValue) {}
                });
                break;
        }
    });

    // Frida official example https://www.frida.re/docs/javascript-api/, search "Interceptor"
    Interceptor.attach(Module.getExportByName(null, 'read'), {
        onEnter: function (args) {
            console.log('Context information:');
            console.log('Context  : ' + JSON.stringify(this.context));
            console.log('Return   : ' + this.returnAddress);
            console.log('ThreadId : ' + this.threadId);
            console.log('Depth    : ' + this.depth);
            console.log('Errornr  : ' + this.err);

            // Save arguments for processing in onLeave.
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.count = args[2].toInt32();
        },
        onLeave: function (result) {
            console.log('----------')
            // Show argument 1 (buf), saved during onEnter.
            var numBytes = result.toInt32();
            if (numBytes > 0) {
            console.log(hexdump(this.buf, { length: numBytes, ansi: true }));
            }
            console.log('Result   : ' + numBytes);
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

print('[*] Running Arophix Hook Test ...')

script.load()
sys.stdin.read()