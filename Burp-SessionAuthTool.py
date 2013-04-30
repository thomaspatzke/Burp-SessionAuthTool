# This Burp extensions provides passive and active scanner checks for
# detection of potential privilege escalation issues caused by
# transmission of user identifiers from the client.

from burp import (IBurpExtender, ITab, IScannerCheck, IScanIssue, IContextMenuFactory, IContextMenuInvocation, IParameter)
from javax.swing import (JPanel, JTable, JButton, JTextField, JLabel, JScrollPane, JMenuItem)
from javax.swing.table import AbstractTableModel
from java.awt import (GridBagLayout, GridBagConstraints)
from array import array

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IContextMenuFactory, IParameter):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Session Authentication Tool")
        self.out = callbacks.getStdout()

        # definition of suite tab
        self.tab = JPanel(GridBagLayout())
        self.tabledata = MappingTableModel()
        self.table = JTable(self.tabledata)
        #self.table.getColumnModel().getColumn(0).setPreferredWidth(50);
        #self.table.getColumnModel().getColumn(1).setPreferredWidth(100);
        self.tablecont = JScrollPane(self.table)
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.anchor = GridBagConstraints.FIRST_LINE_START
        c.gridx = 0
        c.gridy = 0
        c.gridheight = 6
        c.weightx = 0.3
        c.weighty = 0.5
        self.tab.add(self.tablecont, c)

        c = GridBagConstraints()
        c.weightx = 0.1
        c.anchor = GridBagConstraints.FIRST_LINE_START
        c.gridx = 1

        c.gridy = 0
        label_id = JLabel("Identifier:")
        self.tab.add(label_id, c)
        self.input_id = JTextField(20)
        self.input_id.setToolTipText("Enter the identifier which is used by the application to identifiy a particular test user account, e.g. a numerical user id or a user name.")
        c.gridy = 1
        self.tab.add(self.input_id, c)

        c.gridy = 2
        label_content = JLabel("Content:")
        self.tab.add(label_content, c)
        self.input_content = JTextField(20, actionPerformed=self.btn_add_id)
        self.input_content.setToolTipText("Enter some content which is displayed in responses of the application and shows that the current session belongs to a particular user, e.g. the full name of the user.")
        c.gridy = 3
        self.tab.add(self.input_content, c)

        self.btn_add = JButton("Add/Edit Identity", actionPerformed=self.btn_add_id)
        c.gridy = 4
        self.tab.add(self.btn_add, c)

        self.btn_del = JButton("Delete Identity", actionPerformed=self.btn_del_id)
        c.gridy = 5
        self.tab.add(self.btn_del, c)

        callbacks.customizeUiComponent(self.tab)
        callbacks.customizeUiComponent(self.table)
        callbacks.customizeUiComponent(self.tablecont)
        callbacks.customizeUiComponent(self.btn_add)
        callbacks.customizeUiComponent(self.btn_del)
        callbacks.customizeUiComponent(label_id)
        callbacks.customizeUiComponent(self.input_id)
        callbacks.addSuiteTab(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

    def btn_add_id(self, e):
        ident = self.input_id.text
        self.input_id.text = ""
        content = self.input_content.text
        self.input_content.text = ""
        self.tabledata.add_mapping(ident, content)
        self.input_id.requestFocusInWindow()

    def btn_del_id(self, e):
        rows = self.table.getSelectedRows().tolist()
        self.tabledata.del_rows(rows)

    ### ITab ###
    def getTabCaption(self):
        return("SessionAuth")

    def getUiComponent(self):
        return self.tab

    ### IContextMenuFactory ###
    def createMenuItems(self, invocation):
        msgs = invocation.getSelectedMessages()
        if msgs == None or len(msgs) != 1:
            return None
        bounds = invocation.getSelectionBounds()
        if bounds == None or bounds[0] == bounds[1]:
            return None

        msg = None
        if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST or invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            msg = msgs[0].getRequest().tostring()
        if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE or invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
            msg = msgs[0].getResponse().tostring()
        if msg == None:
            return None

        selection = msg[bounds[0]:bounds[1]]
        menuitems = [JMenuItem("Add '" + selection + "' as object id", actionPerformed=self.gen_menu_add_id(selection))]
        if self.tabledata.lastadded != None:
            menuitems.append(JMenuItem("Add '" + selection + "' as content to last added id", actionPerformed=self.gen_menu_add_content(selection)))
        return menuitems

    def gen_menu_add_id(self, ident):
        def menu_add_id(e):
            self.tabledata.add_mapping(ident, "")
        return menu_add_id

    def gen_menu_add_content(self, content):
        def menu_add_content(e):
            self.tabledata.set_lastadded_content(content)
        return menu_add_content

    ### IScannerCheck ###
    def doPassiveScan(self, baseRequestResponse):
        analyzedRequest = self.helpers.analyzeRequest(baseRequestResponse)
        params = analyzedRequest.getParameters()
        ids = self.tabledata.getIds()
        issues = list()

        for param in params:
            value = param.getValue()
            for ident in ids:
                if value == ident:
                    issues.append(SessionAuthPassiveScanIssue(
                        baseRequestResponse.getHttpService(),
                        analyzedRequest.getUrl(),
                        baseRequestResponse,
                        param,
                        ident,
                        self.tabledata.getValue(ident),
                        SessionAuthPassiveScanIssue.foundEqual,
                        self.callbacks
                        ))
                elif value.find(ident) >= 0:
                    issues.append(SessionAuthPassiveScanIssue(
                        baseRequestResponse.getHttpService(),
                        analyzedRequest.getUrl(),
                        baseRequestResponse,
                        param,
                        ident,
                        self.tabledata.getValue(ident),
                        SessionAuthPassiveScanIssue.foundInside,
                        self.callbacks
                        ))
        if len(issues) > 0:
            return issues
        else:
            return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return 1
        else:
            return 0


class SessionAuthPassiveScanIssue(IScanIssue):
    foundEqual = 1                        # parameter value equals identifier
    foundInside = 2                       # identifier was found inside parameter value

    def __init__(self, service, url, httpmsgs, param, ident, value, foundtype, callbacks):
        self.callbacks = callbacks
        self.service = service
        self.findingurl = url
        requestMatch = [array('i', [param.getValueStart(), param.getValueEnd()])]
        responseMatches = self.findAll(httpmsgs.getResponse().tostring(), value)
        self.httpmsgs = [callbacks.applyMarkers(httpmsgs, requestMatch, responseMatches)]
        if responseMatches:
            self.foundInResponse = True
        else:
            self.foundInResponse = False
        self.param = param
        self.ident = ident
        self.value = value
        self.foundtype = foundtype

    def __eq__(self, other):
        return self.param.getType() == other.param.getType() and self.param.getName() == other.param.getName() and self.param.getValue() == other.param.getValue()

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "SessionAuthPassiveScanIssue(" + self.getUrl() + "," + self.param.getType() + "," + self.param.getName + "," + self.param.getValue() + ")\n"

    def findAll(self, searchIn, searchVal):
        found = list()
        length = len(searchVal)
        continueSearch = True
        offset = 0
        while continueSearch:
            pos = searchIn.find(searchVal)
            if pos >= 0:
                found.append(array('i', [pos + offset, pos + length + offset]))
                searchIn = searchIn[pos + length:]
                offset = offset + pos + length
            else:
                continueSearch = False
        if len(found) > 0:
            return found
        else:
            return None

    def getUrl(self):
        return self.findingurl

    def getIssueName(self):
        return "Object Identifier found in Parameter Value"

    def getIssueType(self):
        return 1

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        if self.foundtype == self.foundEqual:
            return "Certain"
        elif self.foundtype == self.foundInside:
            return "Tentative"

    def getParamTypeStr(self):
        paramtype = self.param.getType()
        if paramtype == IParameter.PARAM_URL:
            return "URL parameter"
        elif paramtype == IParameter.PARAM_BODY:
            return "body parameter"
        elif paramtype == IParameter.PARAM_COOKIE:
            return "cookie"
        elif paramtype == IParameter.PARAM_XML:
            return "XML parameter"
        elif paramtype == IParameter.PARAM_XML_ATTR:
            return "XML attribute parameter"
        elif paramtype == IParameter.PARAM_MULTIPART_ATTR:
            return "multipart attribute parameter"
        elif paramtype == IParameter.PARAM_JSON:
            return "JSON parameter"
        else:
            return "parameter"

    def getIssueDetail(self):
        msg = "The " + self.getParamTypeStr() + " <b>" + self.param.getName() + "</b> contains the user identifier <b>" + self.ident + "</b>."
        if self.foundInResponse:
            msg += "\nThe value <b>" + self.value + "</b> associated with the identifier was found in the response. The request is \
            probably suitable for active scan detection of privilege escalation vulnerabilities."
        return msg

    def getRemediationDetail(self):
        return None

    def getIssueBackground(self):
        return "User identifiers submitted in requests are potential targets for parameter tampering attacks. An attacker could try to impersonate other users by \
        replacement of his own user identifier by the id from a different user. This issue was reported because the user identifier previously entered was found in \
        the request."

    def getRemediationBackground(self):
        return "Normally it is not necessary to submit the user identifier in requests to identitfy the user account associated with a session. The user identity should \
        be stored in session data. There are some legitime cases where user identifiers are submitted in requests, e.g. logins or viewing profiles of other users."

    def getHttpMessages(self):
        return self.httpmsgs

    def getHttpService(self):
        return self.service


class MappingTableModel(AbstractTableModel):
    def __init__(self):
        AbstractTableModel.__init__(self)
        self.columnnames = ["User/Object Identifier", "Content"]
        self.mappings = dict()
        self.idorder = list()
        self.lastadded = None

    def getColumnCount(self):
        return len(self.columnnames)

    def getRowCount(self):
        return len(self.mappings)

    def getColumnName(self, col):
        return self.columnnames[col]

    def getValueAt(self, row, col):
        if col == 0:
            return self.idorder[row]
        else:
            return self.mappings[self.idorder[row]]

    def getColumnClass(self, idx):
        return str

    def isCellEditable(self, row, col):
       if col < 1:
           return False
       else:
           return True

    def add_mapping(self, ident, content):
        if ident not in self.mappings:
            self.idorder.append(ident)
        self.mappings[ident] = content
        self.lastadded = ident
        self.fireTableDataChanged()

    def set_lastadded_content(self, content):
        self.mappings[self.lastadded] = content
        self.fireTableDataChanged()

    def del_rows(self, rows):
        rows.sort()
        deleted = 0
        for row in rows:
            delkey = self.idorder[row - deleted]
            del self.mappings[delkey]
            if delkey == self.lastadded:
                self.lastadded = None
            if row - deleted > 0:
                self.idorder = self.idorder[:row - deleted] + self.idorder[row + 1 - deleted:]
            else:
                self.idorder = self.idorder[1:]
            self.fireTableRowsDeleted(row - deleted, row - deleted)
            deleted = deleted + 1

    def setValueAt(self, val, row, col):
        if col == 1:
            self.mappings[self.idorder[row]] = val
            self.fireTableCellUpdated(row, col)

    def getIds(self):
        return self.idorder

    def getValue(self, ident):
        return self.mappings[ident]
