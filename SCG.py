from burp import IBurpExtender, ITab, IHttpListener, IParameter, IRequestInfo
from javax.swing import JPanel, JLabel, JTextField, JButton, JComboBox, JCheckBox, JTextArea, JScrollPane, BoxLayout, JTabbedPane
from java.awt import BorderLayout, GridLayout, Toolkit
from java.awt.datatransfer import StringSelection
from java.io import PrintWriter

class BurpExtender(IBurpExtender, ITab, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("SQLMap Command Generator")

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.registerHttpListener(self)

        self._panel = JPanel(BorderLayout())
        self._mainPanel = JPanel()
        self._mainPanel.setLayout(BoxLayout(self._mainPanel, BoxLayout.Y_AXIS))

        self._urlLabel = JLabel("Target URL:")
        self._urlField = JTextField(40)
        self._mainPanel.add(self._urlLabel)
        self._mainPanel.add(self._urlField)

        self._methodLabel = JLabel("HTTP Method:")
        self._methodCombo = JComboBox(["GET", "POST"])
        self._mainPanel.add(self._methodLabel)
        self._mainPanel.add(self._methodCombo)

        self._paramLabel = JLabel("Parameters to Test (comma-separated):")
        self._paramField = JTextField(40)
        self._mainPanel.add(self._paramLabel)
        self._mainPanel.add(self._paramField)

        self._bodyLabel = JLabel("Request Body:")
        self._bodyField = JTextArea(5, 40)
        self._bodyScrollPane = JScrollPane(self._bodyField)
        self._mainPanel.add(self._bodyLabel)
        self._mainPanel.add(self._bodyScrollPane)

        self._optionsTabs = JTabbedPane()
        self._mainPanel.add(self._optionsTabs)

        self._checkboxPanel = JPanel()
        self._checkboxPanel.setLayout(BoxLayout(self._checkboxPanel, BoxLayout.Y_AXIS))
        
        self._checkboxes = {}
        self._valueFields = {}  # Dictionary to store value input fields
        options = [
            "--random-agent", "--ignore-proxy", "--proxy=<PROXY>", "--tor", "--check-tor", 
            "--delay=<DELAY>", "--timeout=<TIMEOUT>", "--force-ssl", "--cookie=<COOKIE>",
            "--chunked", "--dbms=<DBMS>", "--os=<OS>", "--technique=<TECHNIQUE>", 
            "--level=<LEVEL>", "--risk=<RISK>", "--string=<STRING>", "--not-string=<NOT_STRING>", 
            "--regexp=<REGEXP>", "--code=<CODE>", "--text-only", "--current-user", 
            "--current-db", "--hostname", "--is-dba", "--users", "--passwords", "--roles", 
            "--dbs", "--tables", "--columns", "--schema", "--count", "--dump", "--dump-all", 
            "-D <DB>", "-T <TBL>", "-C <COL>", "-U <USER>", "--sql-query=<SQL_QUERY>", "--sql-shell", "--sql-file=<SQLFILE>", 
            "--os-cmd=<OSCMD>", "--os-shell", "--os-pwn", "--base64=<BASE64PARAM>", "--batch", 
            "--cleanup", "--crawl=<CRAWLDEPTH>", "--flush-session", "--forms", "--fresh-queries", "--hex"
        ]

        for option in options:
            optionPanel = JPanel(BorderLayout())  # Panel to hold checkbox and value field
            checkbox = JCheckBox(option)
            self._checkboxes[option] = checkbox
            optionPanel.add(checkbox, BorderLayout.WEST)

            # Add a text field for options that require a value
            if "=<" in option or option.startswith(("-U", "-T", "-D", "-C")):
                valueField = JTextField(20)
                self._valueFields[option] = valueField
                optionPanel.add(valueField, BorderLayout.CENTER)

            self._checkboxPanel.add(optionPanel)

        self._optionsTabs.add("Options", JScrollPane(self._checkboxPanel))

        buttonPanel = JPanel()
        self._generateButton = JButton("Generate SQLMap Command", actionPerformed=self.generateCommand)
        self._copyButton = JButton("Copy to Clipboard", actionPerformed=self.copyToClipboard)
        buttonPanel.add(self._generateButton)
        buttonPanel.add(self._copyButton)
        self._mainPanel.add(buttonPanel)

        self._outputLabel = JLabel("Generated SQLMap Command:")
        self._outputArea = JTextArea(10, 50)
        self._outputArea.setEditable(False)
        self._outputScrollPane = JScrollPane(self._outputArea)
        outputPanel = JPanel(BorderLayout())
        outputPanel.add(self._outputLabel, BorderLayout.NORTH)
        outputPanel.add(self._outputScrollPane, BorderLayout.CENTER)
        self._mainPanel.add(outputPanel)

        self._panel.add(self._mainPanel, BorderLayout.CENTER)
        callbacks.addSuiteTab(self)
        self._stdout.println("SQLMap Command Generator loaded successfully.")

    def getTabCaption(self):
        return "SQLMap Generator"

    def getUiComponent(self):
        return self._panel

    def generateCommand(self, event):
        try:
            url = self._urlField.getText()
            method = self._methodCombo.getSelectedItem()
            params = self._paramField.getText()
            body = self._bodyField.getText()
            
            command = "sqlmap -u \"{}\"".format(url)
            if method == "POST":
                command += " --data=\"{}\"".format(body)
            if params:
                command += " -p {}".format(params)
            
            for option, checkbox in self._checkboxes.items():
                if checkbox.isSelected():
                    if "=<" in option or option.startswith(("-U", "-T", "-D", "-C")):
                        # Append the value from the corresponding text field
                        value = self._valueFields[option].getText()
                        if value:
                            if option.startswith(("-U", "-T", "-D", "-C")):
                                command += " {} {}".format(option, value)
                            else:
                                command += " {}={}".format(option.split("=<")[0], value)
                    else:
                        command += " {}".format(option)

            self._outputArea.setText(command)
            self._stdout.println("Generated SQLMap Command: " + command)
        except Exception as e:
            self._stderr.println("Error generating SQLMap command: {}".format(str(e)))

    def copyToClipboard(self, event):
        try:
            command = self._outputArea.getText()
            if command:
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(StringSelection(command), None)
                self._stdout.println("SQLMap command copied to clipboard.")
        except Exception as e:
            self._stderr.println("Error copying to clipboard: {}".format(str(e)))
