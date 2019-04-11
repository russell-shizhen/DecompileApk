import frida
import sys

package_name = "com.gemalto.ezio.mobile.sdk.validation"

# Not working ...
def native_hooking_scripts_1():
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

    """
    return hook_code

# Hook the JNI function by function name
def native_hooking_scripts_2():
    hook_code = """
	var moduleName = "libidp-shared.so"; 
    var nativeFuncAddr = 0x00004d10; // $ nm --demangle --dynamic libnative-lib.so | grep "stringFromJNI"

    
    Interceptor.attach (Module.findExportByName (moduleName, "_Smm1KwaVWWLFyACFVKpdeV"), {
        onEnter: function (args) {
            console.log("_Smm1KwaVWWLFyACFVKpdeV called ...");
        },
        // Change the returned String
        onLeave: function (retval) {
            //console.log("ret: " + retval);
            //const dstAddr = Java.vm.getEnv().newStringUtf("Frida is hooking this displayed text from Native layer by function name.");
            //retval.replace(dstAddr);
        }
    });

    """
    return hook_code

# Hook the JNI function by function address -- Not yet working ...
def native_hooking_scripts_3():
    hook_code = """
	var moduleName = "libnative-lib.so"; 
    var nativeFuncAddr = '0x00004d10'; // $ nm --demangle --dynamic libnative-lib.so | grep "stringFromJNI"
    
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
    const addressOfStringFromJni = memAddress(membase, '0x0', '0x00004d10');
    console.log("[+] addressOfStringFromJni: " + addressOfStringFromJni);
    
    Interceptor.attach(ptr(addressOfStringFromJni), {
        onEnter: function (args) {
            console.log("[++] addressOfStringFromJni: " + addressOfStringFromJni);
        },
        onLeave: function (ignoredReturnValue) {

        }
    });

    """
    return hook_code

# Frida official example https://www.frida.re/docs/javascript-api/, search "Interceptor"
def native_hooking_scripts_4():
    hook_code = """

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

# Try enumerateSymbolsSync
def native_hooking_scripts_5():
    hook_code = """

    var moduleName = 'libart.so'; 
    var nativeFuncAddr = '0x00004d10'; // $ nm --demangle --dynamic libnative-lib.so | grep "stringFromJNI"
    
    Java.perform(function () {    
        console.log("moduleName: " + moduleName);
        // see: https://www.frida.re/docs/functions/
        Module.enumerateSymbolsSync(moduleName).forEach(function(symbol){
            console.log("symbol.name: " + symbol.name);
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
            }
        });
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