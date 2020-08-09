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


var myPage = null;

var execHC = "/bin/hc";
var execMT = "maintenancetool";

function Component()
{
    // default constructor
	if (systemInfo.productType === "windows") {
		execHC = "/bin/hc.exe";
		execMT = "maintenancetool.exe";
	}

	component.loaded.connect(this, this.installerLoaded);
}

function RefreshUI()
{
	//HC: if complete is false, then next button is disabled
	myPage.complete = false;

	var dir = myPage.targetDirectory.text;
	myPage.warningInput.setVisible(false);
	myPage.confirmLineEdit.setVisible(false);
	myPage.confirmLineEdit.setText("");
	
	if (installer.fileExists(dir) && installer.fileExists(dir + execHC)) {
        //myPage.warning.setText("<p style=\"color: red\">Existing installation detected, you must backed up your wallets to continue.</p>");
		//myPage.warningInput.setText("<p style=\"color: red\">Please input 'y' to uninstall if you have already backed up your wallets:</p>");

		myPage.warning.setText("<p style=\"color: red\">当前选择的目标目录检测到已安装Paralism，继续安装前将卸载之前安装，卸载后您的钱包将不可恢复！！！或者您也可以选择其他目录来继续安装。</p>");
		myPage.warningInput.setText("<p style=\"color: red\">如果仍然继续，请务必先备份您的钱包，然后在右边文本框中输入‘y’，安装程序将会卸载已安装的Paralism。</p>");
		
		myPage.warningInput.setVisible(true);
		myPage.confirmLineEdit.setVisible(true);
    }
    else if (installer.fileExists(dir)) {
        //myPage.warning.setText("<p style=\"color: red\">Installing in existing directory. It will be wiped on uninstallation.</p>");
		myPage.warning.setText("<p style=\"color: red\">警告：当前目标目录已经存在，Paralism卸载后将会删除目录下所有文件。</p>");
		myPage.complete = true;
    }
    else {
        myPage.warning.setText("");
		myPage.complete = true;
    }
    installer.setValue("TargetDir", dir);
}

Component.prototype.installerLoaded = function()
{
    installer.setDefaultPageVisible(QInstaller.TargetDirectory, false);
    installer.addWizardPage(component, "TargetSelectWidget", QInstaller.TargetDirectory);

    myPage = gui.pageWidgetByObjectName("DynamicTargetSelectWidget");
    //myPage.windowTitle = "Choose Installation Directory";
	myPage.windowTitle = "选择安装目录";
    //myPage.description.setText("Please select where Paralism will be installed:");	
	myPage.description.setText("请选择Paralism安装目录：");
		
	//install event handler
    myPage.targetDirectory.textChanged.connect(this, this.targetDirectoryChanged);
	myPage.confirmLineEdit.textChanged.connect(this, this.confirmLineEditChanged);
	myPage.targetChooser.released.connect(this, this.targetChooserClicked);
	
	myPage.targetDirectory.setText(installer.value("TargetDir"));
}

Component.prototype.targetChooserClicked = function()
{
    var dir = QFileDialog.getExistingDirectory("", myPage.targetDirectory.text);
	if(dir == "") {
		return;
	}
	myPage.targetDirectory.setText(dir);
}

//User select a installation directory
Component.prototype.targetDirectoryChanged = function()
{
	RefreshUI(); 
}

function uninstall()
{
    var dir = installer.value("TargetDir");
	 
	//QMessageBox.information("someid", "Installer", "You must do to continue", QMessageBox.Ok);
		
    if (installer.fileExists(dir) && installer.fileExists(dir + "/" + execMT)) {
		installer.execute(dir + "/" + execMT);
    }
}

Component.prototype.confirmLineEditChanged = function()
{
	var confirmtext = myPage.confirmLineEdit.text;
	if(confirmtext == "y"){
		myPage.complete = true;
		installer.gainAdminRights();
		uninstall();
	}
	else {
		myPage.complete = false;
	}
}


Component.prototype.createOperations = function()
{
    // call default implementation to actually install hc.exe!
    component.createOperations();
	
	if (systemInfo.productType === "windows") {
		
        }
	else if(systemInfo.productType === "osx") {
		//macOS
	}
	else {
		//Linux or Unix
		//Create Shortcut, At first let any user can access these directories.	
		component.addOperation("Execute", "chmod", "a+x", "@TargetDir@/bin");
		component.addOperation("Execute", "chmod", "a+x", "@TargetDir@/bin/lib");
		component.addOperation("Execute", "chmod", "a+x", "@TargetDir@/bin/hyperchain");						
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
