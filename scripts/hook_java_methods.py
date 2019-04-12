import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode_hook_java_methods = """
    Java.perform(function () {
        // Function to hook is defined here
        var MainActivity = Java.use('com.arophix.decompileapk.MainActivity');

        // Whenever button is clicked
        MainActivity.onClick.implementation = function (v) {
            // Show a message to know that the function got called
            send('onClick');

            // Call the original onClick handler
            this.onClick(v);
        };
    });

    Java.perform(function () {
        // Function to hook is defined here
        var MainActivity = Java.use('com.arophix.decompileapk.MainActivity');

        // Whenever button is clicked
        MainActivity.isPhoneRooted.implementation = function (v) {
            // Show a message to know that the function got called
            send("Called - isPhoneRooted()");
            return false;
        };
    });
"""

process = frida.get_usb_device().attach('com.arophix.decompileapk')
script = process.create_script(jscode_hook_java_methods)
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()
