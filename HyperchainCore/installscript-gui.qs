/****************************************************************************
**Copyright 2016-2019 hyperchain.net (Hyperchain)
**Distributed under the MIT software license, see the accompanying
**file COPYING or https://opensource.org/licenses/MIT.

**Permission is hereby granted, free of charge, to any person obtaining a copy of this 
**software and associated documentation files (the "Software"), to deal in the Software
**without restriction, including without limitation the rights to use, copy, modify, merge,
**publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
**to whom the Software is furnished to do so, subject to the following conditions:
**The above copyright notice and this permission notice shall be included in all copies or
**substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
**INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
**PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
**FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
**OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
**DEALINGS IN THE SOFTWARE.
*/


function Component()
{
    // default constructor
}

Component.prototype.createOperations = function()
{
    // call default implementation to actually install hc.exe!
    component.createOperations();
	
	if (systemInfo.productType === "windows") {
		component.addOperation("CreateShortcut", "@TargetDir@/gui/Paralism-Lite.exe", "@DesktopDir@/Paralism-Lite.lnk",
            "workingDirectory=@TargetDir@/gui", "@TargetDir@/gui/Paralism-Lite.exe",
            "iconId=1", "description=Open HyperChain GUI Application");
    }
	else {
		
		//Create Shortcut, At first let any user can access these directories.				
		component.addOperation("Execute", "chmod", "a+x", "@TargetDir@/gui");
		component.addOperation("Execute", "chmod", "a+x", "@TargetDir@/gui/lib");
		component.addOperation("Execute", "chmod", "a+x", "@TargetDir@/gui/translations");
		component.addOperation("Execute", "chmod", "-R", "a+x", "@TargetDir@/gui/plugins");
		component.addOperation("Execute", "chmod", "a+x", "@TargetDir@/gui/Paralism-Lite");
        component.addOperation("Execute", "chmod", "a+x", "@TargetDir@/gui/Paralism-Lite-Helper");
		component.addOperation("CreateDesktopEntry", 
								"/usr/share/applications/paralism.desktop",				"Type=Application\nExec=@TargetDir@/gui/Paralism-Lite-Helper\nName=Paralism-Lite\nGenericName=Paralism-Lite\nIcon=@TargetDir@/gui/logo.ico\nTerminal=false\nCategories=Development;"
							  );
		
		
    }
}

/*
#!/bin/sh
#appname=`basename $0 | sed s,\.sh$,,`
#appname=hc

dirname=`dirname $0`
tmp="${dirname#??}"

if [ "${dirname%$tmp}" != "/" ]; then
dirname=$PWD/$dirname
fi

LD_LIBRARY_PATH=$dirname:$dirname/lib
export LD_LIBRARY_PATH
$dirname/$appname $*
*/
