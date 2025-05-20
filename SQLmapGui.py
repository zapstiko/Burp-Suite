# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, ITab
from java.util import ArrayList
from javax.swing import (
    JPanel, JButton, JCheckBox, JScrollPane, JTextPane,
    JLabel, BoxLayout, JTable, JMenuItem, ListSelectionModel, JSplitPane,
    JTextField, JComboBox
)
from javax.swing.table import DefaultTableModel
from javax.swing.text import SimpleAttributeSet, StyleConstants
from java.awt import Color, Font, BorderLayout, GridLayout
import subprocess
import threading
import time
import os

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQLMap GUI")

        self.saved_requests = []
        self.proc = None

        self.panel = JPanel(BorderLayout())

        self.req_table_model = DefaultTableModel(["Saved Requests"], 0)
        self.req_table = JTable(self.req_table_model)
        self.req_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        table_scroll = JScrollPane(self.req_table)

        self.options_panel = JPanel(GridLayout(0, 3, 5, 5))
        self.options = []

        def add_option(label, takes_value=False, default_value=""):
            box = JCheckBox(label)
            field = JTextField(default_value) if takes_value else None
            self.options.append((box, field))
            self.options_panel.add(box)
            self.options_panel.add(field if field else JPanel())

        def add_dropdown(label, values):
            box = JCheckBox(label)
            dropdown = JComboBox(values)
            self.options.append((box, dropdown))
            self.options_panel.add(box)
            self.options_panel.add(dropdown)

        add_option("--risk", True, "3")
        add_option("--level", True, "5")
        add_option("--tables")
        add_option("--dump")
        add_option("--columns")
        add_option("--current-user")
        add_option("--current-db")
        add_option("--passwords")
        add_option("--dbs")
        add_option("--dump-all")
        add_option("--banner")
        add_option("--flush-session")
        add_option("--forms")
        add_option("--crawl", True)
        add_dropdown("--threads", [str(i) for i in range(1, 11)])
        add_option("--delay", True)
        add_dropdown("--technique", ["", "B", "T", "E", "U", "S", "Q", "A"])
        add_option("--proxy", True, "http://127.0.0.1:8080")
        add_option("--random-agent")
        add_option("--read-file", True)
        add_option("--file-write", True)
        add_option("--file-dest", True)
        add_option("--tamper", True, "space2comment")
        add_option("--dbms", True)
        add_option("-D", True)
        add_option("-T", True)
        add_option("-C", True)

        self.output_pane = JTextPane()
        self.output_pane.setEditable(False)
        self.output_pane.setFont(Font("Monospaced", Font.BOLD, 16))
        output_scroll = JScrollPane(self.output_pane)

        self.run_button = JButton("Run SQLMap", actionPerformed=self.run_sqlmap)
        self.stop_button = JButton("Stop", actionPerformed=self.kill_sqlmap)
        self.button_panel = JPanel()
        self.button_panel.add(self.run_button)
        self.button_panel.add(self.stop_button)

        self.left_panel = JPanel(BorderLayout())
        top_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, self.options_panel)
        top_split.setResizeWeight(0.5)
        self.left_panel.add(top_split, BorderLayout.CENTER)

        self.right_panel = JPanel(BorderLayout())
        self.right_panel.add(output_scroll, BorderLayout.CENTER)
        self.right_panel.add(self.button_panel, BorderLayout.SOUTH)

        split_main = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.left_panel, self.right_panel)
        split_main.setResizeWeight(0.35)
        self.panel.add(split_main, BorderLayout.CENTER)

        callbacks.customizeUiComponent(self.panel)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    def getTabCaption(self):
        return "SQLMap GUI"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu.add(JMenuItem("Send to SQLMap", actionPerformed=lambda x: self.save_request(invocation)))
        return menu

    def save_request(self, invocation):
        reqs = invocation.getSelectedMessages()
        if not reqs:
            return
        request_info = self._helpers.analyzeRequest(reqs[0])
        headers = request_info.getHeaders()
        body = self._helpers.bytesToString(reqs[0].getRequest()[request_info.getBodyOffset():])
        timestamp = int(time.time())
        filename = "/tmp/sqlmap-%d.req" % timestamp
        with open(filename, "w") as f:
            for h in headers:
                f.write(h + "\n")
            f.write("\n" + body)
        self.saved_requests.append(filename)
        self.req_table_model.addRow([filename])
        self.append_output("[+] Saved: %s\n" % filename, "gray")

    def run_sqlmap(self, _):
        row = self.req_table.getSelectedRow()
        if row == -1:
            self.append_output("[-] No request selected.\n", "red")
            return
        filename = self.req_table_model.getValueAt(row, 0)
        cmd = ["/usr/bin/sqlmap", "-r", filename, "--batch"]
        for checkbox, field in self.options:
            if checkbox.isSelected():
                if isinstance(field, JComboBox):
                    value = field.getSelectedItem()
                    if value:
                        cmd.extend([checkbox.getText(), str(value)])
                elif field:
                    value = field.getText().strip()
                    if value:
                        cmd.extend([checkbox.getText(), value])
                else:
                    cmd.append(checkbox.getText())
        self.append_output("[+] Running: %s\n\n" % " ".join(cmd), "gray")
        def execute():
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                for line in iter(self.proc.stdout.readline, b''):
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="ignore").strip()
                    if "vulnerable" in decoded:
                        self.append_output(decoded + "\n", "green")
                    elif "[INFO]" in decoded:
                        self.append_output(decoded + "\n", "gray")
                    elif "[WARNING]" in decoded:
                        self.append_output(decoded + "\n", "orange")
                    elif "[CRITICAL]" in decoded or "[ERROR]" in decoded:
                        self.append_output(decoded + "\n", "red")
                    else:
                        self.append_output(decoded + "\n", "gray")
                self.proc.stdout.close()
                self.proc = None
            except Exception as e:
                self.append_output("[!] Exception: %s\n" % str(e), "red")
        threading.Thread(target=execute).start()

    def kill_sqlmap(self, _):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.append_output("[!] SQLMap process terminated.\n", "red")
            self.proc = None
        else:
            self.append_output("[!] No active scan to kill.\n", "orange")

    def append_output(self, text, color):
        doc = self.output_pane.getStyledDocument()
        style = SimpleAttributeSet()
        if color == "red":
            StyleConstants.setForeground(style, Color.RED)
        elif color == "orange":
            StyleConstants.setForeground(style, Color.ORANGE)
        elif color == "green":
            StyleConstants.setForeground(style, Color.GREEN)
        else:
            StyleConstants.setForeground(style, Color.LIGHT_GRAY)
        StyleConstants.setFontSize(style, 20)
        StyleConstants.setBold(style, True)
        doc.insertString(doc.getLength(), text, style)
        self.output_pane.setCaretPosition(doc.getLength())