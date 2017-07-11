/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.fieldenumeration;

import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.ButtonGroup;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.model.NameValuePair;
import org.zaproxy.zap.model.ParameterParser;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.utils.ZapTextField;

public class FieldEnumeration extends AbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger.getLogger(FieldEnumeration.class);
    private static final String CSV_EXTENSION = ".csv";
    private HttpSender httpSender;

    private JPanel jPanel = new JPanel();
    private JTabbedPane tp = new JTabbedPane();
    private JPanel formF = new JPanel();
    private JPanel panel = new JPanel();
    private JLabel printURL = new JLabel();
    private DefaultTableModel model = new DefaultTableModel();
    private JTable jTable = new JTable();
    private JButton buttonOK = new JButton(Constant.messages.getString("fieldenumeration.submit"));
    private JLabel blacklist =
            new JLabel(Constant.messages.getString("fieldenumeration.blacklist"));
    private JTextArea blackText = new JTextArea(5, 5);
    private JTextArea whiteText = new JTextArea(5, 5);
    private JLabel whitelist =
            new JLabel(Constant.messages.getString("fieldenumeration.whitelist"));
    private JComboBox<String> params = new JComboBox<String>();
    private JComboBox<String> charSets = new JComboBox<String>();
    private String selectedChars = null;
    private GridBagConstraints c1 = new GridBagConstraints();
    private JTextField preField = new JTextField();
    private JTextField lowerR = new JTextField();
    private JTextField highR = new JTextField();
    private JTextField postField = new JTextField();
    private Font font = new Font("Courier", Font.BOLD, 12);
    private JScrollPane spBlack = new JScrollPane(blackText);
    private JScrollPane spWhite = new JScrollPane(whiteText);
    private JProgressBar jProgressBar = new JProgressBar();

    private ButtonGroup group = new ButtonGroup();
    private JTextField regex = new JTextField(20);

    private List<NameValuePair> listParam = new ArrayList<>();
    private HistoryReference historyRef;
    private HttpMessage msg;
    private String field = null;

    public FieldEnumeration() throws HeadlessException {
        super();
        initialize();
    }

    public FieldEnumeration(Frame arg0, boolean arg1) throws HeadlessException {
        super(arg0, arg1);
        initialize();
    }

    private void persistAndShowMessage(final HttpMessage httpMessage) {
        if (!EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            persistAndShowMessage(httpMessage);
                        }
                    });
            return;
        }

        try {
            Session session = Model.getSingleton().getSession();
            HistoryReference ref =
                    new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, httpMessage);
            final ExtensionHistory extHistory =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
            if (extHistory != null) {
                extHistory.addHistory(ref);
            }
            SessionStructure.addPath(Model.getSingleton().getSession(), ref, httpMessage);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.warn("Failed to persist message sent:", e);
        }
    }

    public List<NameValuePair> getParamList() {
        return listParam;
    }

    protected String getEscapedName(HttpMessage msg, String name) {
        return name != null ? AbstractPlugin.getURLEncode(name) : "";
    }

    private String setParameter(
            HttpMessage msg,
            NameValuePair originalPair,
            String name,
            String value,
            boolean escaped) {
        ParameterParser parser;
        parser =
                Model.getSingleton()
                        .getSession()
                        .getFormParamParser(msg.getRequestHeader().getURI().toString());
        StringBuilder sb = new StringBuilder("");
        String encodedValue = new String("");

        try {
            encodedValue =
                    (escaped) ? value : URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ignore) {
        }

        NameValuePair pair;
        boolean isAppended = true;

        for (int i = 0; i < getParamList().size(); i++) {
            pair = getParamList().get(i);

            if (pair.getName() == name) {
                isAppended = paramAppend(sb, getEscapedName(msg, name), encodedValue, parser);
            } else {
                try {
                    isAppended =
                            paramAppend(
                                    sb,
                                    getEscapedName(msg, pair.getName()),
                                    URLEncoder.encode(
                                            pair.getValue(), StandardCharsets.UTF_8.name()),
                                    parser);
                } catch (UnsupportedEncodingException ignore) {
                }
            }

            if (isAppended && i < getParamList().size() - 1) {
                sb.append(parser.getDefaultKeyValuePairSeparator());
            }
        }

        if (sb.length() == 0) {
            // No original query string
            sb.append(encodedValue);
        }
        String query = sb.toString();
        msg.getRequestBody().setBody(query);
        return query;
    }

    private boolean paramAppend(
            StringBuilder sb, String name, String value, ParameterParser parser) {
        boolean isEdited = false;

        if (name != null) {
            sb.append(name);
            isEdited = true;
        }

        if (value != null) {
            sb.append(parser.getDefaultKeyValueSeparator());
            sb.append(value);
            isEdited = true;
        }

        return isEdited;
    }

    private void initialize() {
        this.setTitle(Constant.messages.getString("fieldenumeration.field.popup"));
        this.setContentPane(getJPanel());

        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(400, 400);
        }

        pack();
    }

    private void start(
            final int start,
            final int end,
            final String pre,
            final String post,
            final String regStr,
            final NameValuePair Original) {

        final StringBuilder iChars = new StringBuilder();
        final StringBuilder lChars = new StringBuilder();

        final Runnable runnable =
                new Runnable() {

                    @Override
                    public void run() {
                        // Current runnable code
                        for (int ch = start; ch < end; ch++) {
                            jProgressBar.setValue(ch);

                            String chars = Character.toString((char) ch);

                            String letter;

                            if (pre != null && post != null) {
                                letter = pre.concat(chars);
                                letter = letter.concat(post);
                            } else if (pre != null && post == null) {
                                letter = pre.concat(chars);
                            } else if (pre == null && post != null) {
                                letter = chars.concat(post);
                            } else {
                                letter = chars;
                            }

                            HttpMessage message = msg.cloneRequest();

                            setParameter(message, Original, field, letter, false);
                            message.getRequestHeader()
                                    .setContentLength(message.getRequestBody().length());
                            try {
                                gethttpSender().sendAndReceive(message, false);
                            } catch (IOException ioe) {
                                throw new IllegalArgumentException(
                                        "IO error in sending request: "
                                                + ioe.getClass()
                                                + ": "
                                                + ioe.getMessage(),
                                        ioe);
                            }
                            String response = message.getResponseBody().toString();
                            Pattern pattern = Pattern.compile(regStr);
                            Matcher matcher = pattern.matcher(response);
                            if (matcher.find()) {
                                model.addRow(
                                        new Object[] {
                                            letter,
                                            Constant.messages.getString("fieldenumeration.failed")
                                        });
                                iChars.append(letter).append(", ");
                            } else {
                                model.addRow(
                                        new Object[] {
                                            letter,
                                            Constant.messages.getString("fieldenumeration.success")
                                        });
                                lChars.append(letter).append(", ");
                            }
                            persistAndShowMessage(message);
                        }
                        blackText.append(iChars.toString());
                        whiteText.append(lChars.toString());
                    }
                };

        Thread thread = new Thread(runnable);
        thread.start();
    }

    private JPanel getJPanel() {
        panel.setSize(new Dimension(600, 600));
        panel.setVisible(true);
        tp.add(Constant.messages.getString("fieldenumeration.field.popup"), jPanel);
        jPanel.setLayout(new GridBagLayout());
        c1.fill = GridBagConstraints.HORIZONTAL;
        jPanel.setSize(new Dimension(600, 600));
        c1.gridx = 0;
        c1.gridy = 0;
        JLabel url = new JLabel(Constant.messages.getString("fieldenumeration.url"));
        url.setFont(font);
        jPanel.add(url, c1);
        c1.anchor = GridBagConstraints.NORTH;
        c1.gridx = 1;
        c1.gridy = 0;
        jPanel.add(printURL, c1);
        c1.gridwidth = 2;
        c1.gridx = 0;
        c1.gridy = 1;
        JLabel enterRegex = new JLabel(Constant.messages.getString("fieldenumeration.enter.regex"));
        enterRegex.setFont(font);
        jPanel.add(enterRegex, c1);
        c1.gridx = 0;
        c1.gridy = 2;
        jPanel.add(regex, c1);
        c1.gridx = 0;
        c1.gridy = 3;
        JLabel selectChars =
                new JLabel(Constant.messages.getString("fieldenumeration.select.chars"));
        selectChars.setFont(font);
        jPanel.add(selectChars, c1);
        charSets.addItem(Constant.messages.getString("fieldenumeration.ascii"));
        charSets.addItem(Constant.messages.getString("fieldenumeration.utf"));
        charSets.addItem(Constant.messages.getString("fieldenumeration.ebcidic"));
        c1.gridx = 0;
        c1.gridy = 4;
        jPanel.add(charSets, c1);
        c1.gridx = 0;
        c1.gridy = 5;
        JLabel formParam = new JLabel(Constant.messages.getString("fieldenumeration.form.param"));
        formParam.setFont(font);
        jPanel.add(formParam, c1);
        formParam.setFont(font);
        jPanel.add(formParam, c1);
        c1.gridx = 0;
        c1.gridy = 6;
        jPanel.add(params, c1);
        c1.gridx = 0;
        c1.gridy = 7;
        JLabel prefix = new JLabel(Constant.messages.getString("fieldenumeration.prefix"));
        prefix.setFont(font);
        jPanel.add(prefix, c1);
        c1.gridx = 0;
        c1.gridy = 8;
        preField.setColumns(10);
        jPanel.add(preField, c1);
        c1.gridx = 0;
        c1.gridy = 9;
        JLabel postfix = new JLabel(Constant.messages.getString("fieldenumeration.postfix"));
        postfix.setFont(font);
        jPanel.add(postfix, c1);
        c1.gridx = 0;
        c1.gridy = 10;
        postField.setColumns(10);
        jPanel.add(postField, c1);
        c1.gridx = 0;
        c1.gridy = 11;
        JLabel range = new JLabel(Constant.messages.getString("fieldenumeration.range"));
        range.setFont(font);
        jPanel.add(range, c1);
        c1.gridx = 0;
        c1.gridy = 12;
        JLabel fromR = new JLabel(Constant.messages.getString("fieldenumeration.range.from"));
        fromR.setFont(font);
        jPanel.add(fromR, c1);
        c1.gridx = 0;
        c1.gridy = 13;
        lowerR.setColumns(10);
        jPanel.add(lowerR, c1);
        c1.gridx = 0;
        c1.gridy = 14;
        JLabel toR = new JLabel(Constant.messages.getString("fieldenumeration.range.to"));
        toR.setFont(font);
        jPanel.add(toR, c1);
        c1.gridx = 0;
        c1.gridy = 15;
        highR.setColumns(10);
        jPanel.add(highR, c1);
        c1.gridx = 0;
        c1.gridy = 16;
        jPanel.add(buttonOK, c1);
        c1.gridx = 0;
        c1.gridy = 17;
        jProgressBar.setStringPainted(true);
        jPanel.add(jProgressBar, c1);
        c1.gridx = 0;
        c1.gridy = 18;
        blacklist.setFont(font);
        jPanel.add(blacklist, c1);
        c1.gridx = 0;
        c1.gridy = 19;
        jPanel.add(spBlack, c1);
        c1.gridx = 0;
        c1.gridy = 20;
        whitelist.setFont(font);
        jPanel.add(whitelist, c1);
        c1.gridx = 0;
        c1.gridy = 21;
        jPanel.add(spWhite, c1);

        tp.add("Forms", formF);

        panel.add(tp);

        buttonOK.addActionListener(
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent event) {

                        field = (String) params.getSelectedItem();
                        selectedChars = (String) charSets.getSelectedItem();
                        String pre = preField.getText();
                        String post = postField.getText();
                        String regexStr = regex.getText();
                        // Result tab
                        model.addColumn(Constant.messages.getString("fieldenumeration.chars"));
                        model.addColumn(Constant.messages.getString("fieldenumeration.result"));
                        jTable.setModel(model);
                        // end
                        JTextField tf = new JTextField();
                        tf.setEditable(false);
                        DefaultCellEditor editor = new DefaultCellEditor(tf);
                        jTable.setDefaultEditor(FieldEnumeration.class, editor);

                        httpSender = gethttpSender();
                        try {
                            msg = historyRef.getHttpMessage().cloneRequest();
                        } catch (HttpMalformedHeaderException | DatabaseException mhe) {
                            throw new IllegalArgumentException("Malformed header error.", mhe);
                        }
                        NameValuePair Original = null;
                        for (org.zaproxy.zap.model.NameValuePair parameter : listParam) {
                            if (field == parameter.getName()) {
                                Original = parameter;
                                break;
                            }
                        }

                        int start = 0;
                        int end = 0;

                        if (!lowerR.getText().isEmpty() && !highR.getText().isEmpty()) {
                            try {
                                start = Integer.parseInt(lowerR.getText());
                            } catch (NumberFormatException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                            try {
                                end = Integer.parseInt(highR.getText());
                            } catch (NumberFormatException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        } else {
                            if (selectedChars == "US-ASCII") {
                                start = 0;
                                end = 128;
                            } else if (selectedChars == "UTF-8") {
                                start = 0;
                                end = 513;
                            } else {
                                start = 0;
                                end = 226;
                            }
                        }

                        blackText.setText("");
                        whiteText.setText("");

                        start(start, end, pre, post, regexStr, Original);
                    }
                });

        pack();

        return panel;
    }

    public HistoryReference getHistoryRef() {
        return historyRef;
    }

    private HttpSender gethttpSender() {
        if (httpSender == null) {
            httpSender =
                    new HttpSender(
                            Model.getSingleton().getOptionsParam().getConnectionParam(),
                            false,
                            HttpSender.MANUAL_REQUEST_INITIATOR);
        }
        return httpSender;
    }

    public void setHistoryRef(HistoryReference historyRef) {
        this.historyRef = historyRef;
        StringBuilder sb = new StringBuilder();
        sb.append(historyRef.getURI().toString());
        printURL.setText(sb.toString());

        // formF.removeAll();
        formF.setLayout(new GridBagLayout());
        GridBagConstraints gbcForm = new GridBagConstraints();
        gbcForm.gridy = 0;
        gbcForm.anchor = GridBagConstraints.NORTH;

        try {
            listParam =
                    Model.getSingleton()
                            .getSession()
                            .getParameters(historyRef.getHttpMessage(), HtmlParameter.Type.form);
            for (org.zaproxy.zap.model.NameValuePair parameter : listParam) {
                JRadioButton button = new JRadioButton(parameter.getName());
                group.add(button);
                gbcForm.gridx = 0;
                gbcForm.fill = GridBagConstraints.NONE;
                formF.add(button, gbcForm);
                params.addItem(parameter.getName());

                ZapTextField textField = new ZapTextField(parameter.getValue());
                textField.setColumns(10);

                gbcForm.gridx = 1;
                gbcForm.fill = GridBagConstraints.HORIZONTAL;
                formF.add(textField, gbcForm);

                gbcForm.gridy++;
            }
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
