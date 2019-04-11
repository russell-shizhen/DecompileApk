import frida
import sys

package_name = "com.arophix.decompileapk"


def get_messages_from_js(message, data):
            #print(message)
            print (message['payload'])
 

def instrument_debugger_checks():
    hook_code = """
	var didHookApis = false;
	Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
	  onEnter: function (args) {
	    this.path = Memory.readUtf8String(args[0]);
		console.log(this.path);
	  },
	  onLeave: function (retval) {
	    if(!retval.isNull() && this.path.indexOf('libnative-lib.so')!== -1 && !didHookApis) {
		  didHookApis = true;
	      console.log("File loaded hooking");
	      hooknative2();
	      // ...
	    }
	  }
	});
	function hooknative2(){
        Interceptor.attach (Module.findExportByName ( "libnative-lib.so", "Java_com_devadvance_rootinspector_Root_checkifstream"), {
                onLeave: function (retval) {
                    retval.replace(0);
        }
        });
    }
    
    """
    return hook_code

device=frida.get_usb_device()
#run package
process = device.attach("com.arophix.decompileapk")
script = process.create_script(instrument_debugger_checks())
script.on('message',get_messages_from_js)
print('[*] Running IDP Hook Test ...')
script.load()
sys.stdin.read()