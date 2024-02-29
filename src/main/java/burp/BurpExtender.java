package burp;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.border.Border;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener,IMessageEditorController,IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPane;
    private List<String> logUrl = new ArrayList<String>();
    private List<LogEntry> log = new ArrayList<LogEntry>();
    private static final List<Rule> rule = new ArrayList<Rule>();
    public RuleTableMoudle ruleTableMoudle = new RuleTableMoudle();
    public RuleTable ruleTable = new RuleTable(ruleTableMoudle);
    private Boolean activeFlag = false;
    public IMessageEditor requestViewer;
    public IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    public String links;
    public JTextArea jTextArea;
    public IHttpRequestResponse item;
    public String file_path;
    public String regex;
    public Clipboard clipboard;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("嗅探JS");

        callbacks.registerContextMenuFactory(this);

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                // main split pane
                mainPane = new JPanel(new BorderLayout());
                JTabbedPane tbs = new JTabbedPane();//标签页
                Input input = new Input();//配置页
                Output output = new Output();//结果页
                tbs.add(input, "配置");
                tbs.add(output, "结果");
                mainPane.add(tbs, BorderLayout.CENTER);

                // customize our UI components
                callbacks.customizeUiComponent(mainPane);


                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    //
    // implement ITab
    //
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation var1){
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>();
        listMenuItems.add(new Menu1(var1));
        listMenuItems.add(new Menu2(var1));
        return listMenuItems;
    }
    public class Menu1 extends JMenuItem{
        public Menu1(IContextMenuInvocation var1){
            this.setText("保存到文件");
            this.addActionListener(new PocTest1(var1));
        }
    }

    public class Menu2 extends JMenuItem{
        public Menu2(IContextMenuInvocation var1){
            this.setText("提取到粘贴板");
            this.addActionListener(new PocTest2(var1));
        }
    }
    public class PocTest1 implements ActionListener {
        public IContextMenuInvocation var1;
        public PocTest1(IContextMenuInvocation var1){
            this.var1 = var1;
        }

        @Override
        public void actionPerformed(ActionEvent e){
            item = var1.getSelectedMessages()[0];
            FileFrame frame = new FileFrame("保存文件");
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        }
    }

    public class PocTest2 implements ActionListener {
        public IContextMenuInvocation var1;
        public PocTest2(IContextMenuInvocation var1){
            this.var1 = var1;
        }

        @Override
        public void actionPerformed(ActionEvent e){
            item = var1.getSelectedMessages()[0];
            PathFrame frame = new PathFrame("提取到粘贴板");
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        }
    }

    public class FileFrame extends JFrame {
        private JPanel mainPane = new JPanel(new FlowLayout(FlowLayout.CENTER));;
        private JTextArea input = new JTextArea();
        private JButton btn = new JButton("确定");

        public FileFrame(String title) throws HeadlessException
        {
            super(title);
            initGUI();
            setSize(450, 80);
            initListeners();
        }

        private void initGUI()
        {
            this.mainPane.add(new JLabel("保存到文件(绝对路径):"));
            Border border = BorderFactory.createLineBorder(Color.BLACK);
            input.setBorder(BorderFactory.createCompoundBorder(border,BorderFactory.createEmptyBorder(5, 5, 5, 5)));
            input.setColumns(30);
            this.mainPane.add(input);
            btn.setSize(10,10);
            this.mainPane.add(btn);
            this.getContentPane().add(mainPane);
        }

        private void initListeners() {
            btn.addActionListener(new ActionListener(){
                @Override
                public void actionPerformed(ActionEvent e)
                {
                    IResponseInfo respInfo = helpers.analyzeResponse(item.getResponse());
                    byte[] content = Arrays.copyOfRange(item.getResponse(),respInfo.getBodyOffset(),item.getResponse().length);
                    file_path = input.getText();
                    FileOutputStream outputStream = null;
                    try {
                        outputStream = new FileOutputStream(file_path);
                        outputStream.write(content);
                    } catch (IOException ioe) {
                        ioe.printStackTrace();
                    } finally {
                        if (outputStream != null) {
                            try {
                                outputStream.close();
                            } catch (IOException ioe) {
                                ioe.printStackTrace();
                            }
                        }
                    }
                    dispose();//关闭打开的窗口
                }
            });
        }
    }

    public class PathFrame extends JFrame {
        private JPanel mainPane = new JPanel(new FlowLayout(FlowLayout.CENTER));;
        private JTextArea input = new JTextArea();
        private JButton btn = new JButton("确定");

        public PathFrame(String title) throws HeadlessException
        {
            super(title);
            initGUI();
            setSize(450, 120);
            initListeners();
        }

        private void initGUI()
        {
            this.mainPane.add(new JLabel("输入正则:"));
            Border border = BorderFactory.createLineBorder(Color.BLACK);
            input.setBorder(BorderFactory.createCompoundBorder(border,BorderFactory.createEmptyBorder(5, 5, 5, 5)));
            input.setColumns(30);
            input.setText("(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')");
            this.mainPane.add(input);
            btn.setSize(10,10);
            this.mainPane.add(btn);
            this.getContentPane().add(mainPane);
        }

        private void initListeners() {
            btn.addActionListener(new ActionListener(){
                @Override
                public void actionPerformed(ActionEvent e)
                {
                    IResponseInfo respInfo = helpers.analyzeResponse(item.getResponse());
                    byte[] content = Arrays.copyOfRange(item.getResponse(),respInfo.getBodyOffset(),item.getResponse().length);
                    regex = input.getText();
                    // 编译正则表达式
                    Pattern pattern = Pattern.compile(regex);
                    // 创建匹配器
                    Matcher matcher = pattern.matcher(new String(content));
                    // 存储所有匹配的字符串
                    Set<String> matchedList = new HashSet<>();
                    // 查找所有匹配的子串
                    while (matcher.find()) {
                        // 获取当前匹配的子串
                        String matched = matcher.group();
                        // 将当前匹配的子串添加到结果中
                        matchedList.add(matched);
                    }
                    // 将HashSet转换为字符串
                    StringBuilder sb = new StringBuilder();
                    for (String element : matchedList) {
                        sb.append(element).append("\n");
                    }
                    StringSelection stsel = new StringSelection(sb.toString());
                    clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    clipboard.setContents(stsel, null);
                    dispose();//关闭打开的窗口
                }
            });
        }
    }

    @Override
    public String getTabCaption()
    {
        return "嗅探JS";
    }

    @Override
    public Component getUiComponent()
    {
        return mainPane;
    }

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        // only process responses
        if (!messageIsRequest)
        {synchronized(log){int row = log.size();
//            String host = helpers.analyzeRequest(messageInfo).getUrl().getHost();
            List<String> headers = helpers.analyzeRequest(messageInfo).getHeaders();
            List<Rule> filterRules = getHostRules();//过滤规则
            boolean process_flag = true;

            if (filterRules.size()>0){//过滤规则不为空
                for(Rule filterRule : filterRules){
                    boolean cannot_find = true;
                    Pattern p = Pattern.compile(filterRule.match);
                    for (String header : headers){
                        Matcher m = p.matcher(header);
                        if(m.find()){cannot_find = false;break;}
                    }
                    if(cannot_find){process_flag = false;break;}
                }
            }

            if(process_flag){
                String url = helpers.analyzeRequest(messageInfo).getUrl().toString();
                if (!logUrl.contains(url)){
                    LogEntry logEntry = new LogEntry(callbacks.saveBuffersToTempFiles(messageInfo), url);
                    //开始处理响应匹配
                    byte[] resp = messageInfo.getResponse();
                    IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
                    String content = new String(Arrays.copyOfRange(resp, responseInfo.getBodyOffset(), resp.length), StandardCharsets.UTF_8);
                    //将内容中的html标签删除
                    Pattern p1 = Pattern.compile("</.*>");
                    Matcher m1 = p1.matcher(content);
                    content =  m1.replaceAll("");

                    String findRules = getBodyRules();//匹配规则
                    Pattern p = Pattern.compile(findRules);
                    Matcher m = p.matcher(content);
                    while (m.find()){
                        String uri = m.group(0).replace("\'", "").replace("\"", "");
                        if (uri.length()==1){uri = "";}//长度为1的，剔除
                        if (uri.contains(" ")){uri = "";}//包含空格的，剔除
                        if (uri.startsWith("//")){uri = "";}//以注释开头的，剔除
                        if (uri.contains("/=")){uri = "";}//包含/=的，剔除
                        if (uri.contains("/-")){uri = "";}//包含/-的，剔除
                        if (uri.contains("/+")){uri = "";}//包含/+的，剔除
                        if (uri.endsWith(":")){uri = "";}//以:结尾的，剔除
                        if (uri.contains(":")){
                            if(uri.split(":").length>=2){uri = "";}//包含2个：的，剔除
                        }
                        if (uri.contains(":")){
                            int index = uri.indexOf(":") + 1;
                            if (!Character.isDigit(uri.charAt(index))){uri = "";}//：后的第一个字符不是数字的，剔除
                        }
                        if (!uri.isEmpty()){logEntry.link.add(uri);}
                    }
                    logUrl.add(logEntry.url);
                    if (logEntry.link.size()!=0){
                        log.add(logEntry);
                    }
                }
            }fireTableRowsInserted(row, row);}}
    }

    //筛选出host过滤的规则
    public List<Rule> getHostRules(){
        List<Rule> headerRules1 = new ArrayList<Rule>();
        for (Rule headerRule1 : rule){
            if (headerRule1.type_id == 0){
                headerRules1.add(headerRule1);
            }
        }
        return headerRules1;
    }

    //筛选出响应匹配的规则
    public String getBodyRules(){
        String bodyRules = "(?:|')(";
        for (Rule bodyRule1 : rule){
            if (bodyRule1.type_id == 1){
//                bodyRules.add(bodyRule1);
                bodyRules = bodyRules + bodyRule1.match + "|";
            }
        }
        return bodyRules.substring(0,bodyRules.length()-1) + ")(?:|')";
    }

    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 2;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "被嗅探的js";
            case 1:
                return "嗅探到的URI数量";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url;
            case 1:
                return logEntry.link.size();
            default:
                return "";
        }
    }


    //
    // extend JTable to handle cell selection
    //

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            links ="";
            for (String item : logEntry.link){
                links = links + "\n" + item;
            }
            jTextArea.setText(links);

            super.setSelectionBackground(Color.orange);
            super.changeSelection(row, col, toggle, extend);
        }
    }

    //
    // class to hold details of each log entry
    //

    private static class LogEntry
    {
        final String url;
        public HashSet<String> link;
        final IHttpRequestResponsePersisted requestResponse;


        LogEntry(IHttpRequestResponsePersisted requestResponse,String url)
        {
            this.url = url;
            this.requestResponse = requestResponse;
            link = new HashSet<>();
        }
    }


    private class RuleTableMoudle extends AbstractTableModel
    {
        public RuleTableMoudle(){}

        @Override
        public int getRowCount()
        {
            return rule.size();
        }

        @Override
        public int getColumnCount(){return 3;}

        @Override
        public String getColumnName(int column){
            switch (column)
            {
                case 0:
                    return "类别";
                case 1:
                    return "匹配";
                case 2:
                    return "注解";
                default:
                    return "";
            }
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex)
        {
            Rule rules = rule.get(rowIndex);
            switch (columnIndex)
            {
                case 0:
                    if (rules.type_id==0){return "请求过滤规则";}
                    else if(rules.type_id==1){return "响应匹配规则";}{
                    return "响应匹配规则";
                }
                case 1:
                    return rules.match;
                case 2:
                    return rules.commit;
                default:
                    return "";
            }
        }
    }


    //规则，从配置里获取
    private class Rule
    {
        public int type_id;
        public String match;
        public String commit;

        public Rule(int type_id,String match,String commit){
            this.type_id = type_id;
            this.match =  match;
            this.commit = commit;
        }
    }

    private class RuleTable extends JTable
    {
        public RuleTable(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            super.setSelectionBackground(Color.orange);
            super.changeSelection(row, col, toggle, extend);
        }
    }


    private class Input extends JPanel {
        private JSplitPane splitPane;
        private JButton add_btn;
        private JButton del_btn;
        private JButton start_btn;
    public Input()
    {
        super(new BorderLayout());
        initGUI();
        initListeners();
        //默认有1条请求过滤规则
        rule.add(new Rule(0,"(^GET /.*\\.js)|(^GET /.*\\.htm)","只处理JS和HTM文件"));
        //默认有4条响应匹配规则
        rule.add(new Rule(1,"((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})","匹配完整的URI"));
        rule.add(new Rule(1,"((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})","匹配../../"));
        rule.add(new Rule(1,"([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/][^\"|']{0,}|))","匹配长度为4的后缀"));
        rule.add(new Rule(1,"([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|))","匹配常见的文件"));
        rule.add(new Rule(1,"(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')",""));
        ruleTableMoudle.fireTableStructureChanged();
    }

    private void initGUI(){
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(1.0/3.0);
        splitPane.setLeftComponent(createRulesPane());
        splitPane.setRightComponent(createReadmePane());
        this.add(splitPane);
    }

    //使用说明
    private JComponent createReadmePane(){
        JPanel readmePane = new JPanel(new BorderLayout());
        JTextArea txtMsg = new JTextArea();
        txtMsg.setEditable(false);
        txtMsg.setText("==========嗅探js By hanfei  ==========\n" +
                "\n" +
                "对js文件，通过匹配规则，筛选出其中到URI地址\n" +
                "btw：请求过滤规则采用并集的关系，响应过滤规则采用或集的关系\n" +
                "\n" +
                "#####1>使用说明：\n" +
                "\n" +
                "1、请求过滤设置：过滤规则math设置为 ^Host:.*example.com$，则只处理example.com域名\n" +
                "2、默认已设置多条匹配规则"
        );
        txtMsg.setBackground(BurpExtender.this.getUiComponent().getBackground());
        readmePane.add(txtMsg);
        return readmePane;
    }

    private JComponent createRulesPane(){
        JPanel rulesPane = new JPanel(new BorderLayout());

        //按键,创建3行1列
        JPanel btnPane = new JPanel();
        add_btn = new JButton("添加规则");
        add_btn.setSize(10,10);
        del_btn = new JButton("删除规则");
        del_btn.setSize(10,10);
        start_btn = new JButton("开启嗅探");
        start_btn.setSize(10,10);
        btnPane.add(add_btn);
        btnPane.add(del_btn);
        btnPane.add(start_btn);

        //规则列表
        JScrollPane ruleScrollPane = new JScrollPane(ruleTable);

        rulesPane.add(btnPane,BorderLayout.SOUTH);
        rulesPane.add(ruleScrollPane,BorderLayout.CENTER);
        return rulesPane;
    }

    private void initListeners() {
        add_btn.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e)
            {
                ConfigFrame frame = new ConfigFrame("规则编辑");
                frame.setLocationRelativeTo(null);
                frame.setVisible(true);
            }
        });
        del_btn.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e)
            {
                //删除数据，而不是删除JTable的展示
                rule.remove(ruleTable.getSelectedRow());
                ruleTableMoudle.fireTableStructureChanged();
            }
        });
        start_btn.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e)
            {
                activeFlag = !activeFlag;
                if (activeFlag){
                    start_btn.setBackground(Color.CYAN);
                    start_btn.setText("关闭嗅探");
                }else {
                    start_btn.setBackground(Color.WHITE);
                    start_btn.setText("开启嗅探");
                }
            }
        });
    }
}

public class ConfigFrame extends JFrame {
    public JPanel mainPane = new JPanel(new BorderLayout());
    public JComboBox cmb1=new JComboBox();//类别选择框
    public JTextField match_input = new JTextField("^Host:.*example.com$");//匹配的字符串
    public JTextField commit_input = new JTextField();//注解的字符串
    private JButton btn = new JButton("确定");

    public ConfigFrame(String title) throws HeadlessException
    {
        super(title);
        initGUI();
        setSize(450, 150);
        initListeners();
    }

    private void initGUI()
    {
        this.mainPane.add(createCbmPane(), BorderLayout.NORTH);
        this.mainPane.add(createRulePane(), BorderLayout.CENTER);
        this.mainPane.add(createBtnPane(),BorderLayout.SOUTH);
        this.getContentPane().add(mainPane);
    }

    private JComponent createCbmPane()
    {
        JPanel cbmPane = new JPanel(new FlowLayout(FlowLayout.CENTER));

        //类别选择框
        cmb1.addItem("请求过滤规则");
        cmb1.addItem("响应匹配规则");

        cbmPane.add(new JLabel("类别:"));
        cbmPane.add(cmb1);

        return cbmPane;
    }

    private JComponent createRulePane(){
        JPanel rulePane = new JPanel(new FlowLayout(FlowLayout.CENTER));
        rulePane.add(new JLabel("Match:"));
        match_input.setColumns(38);
        rulePane.add(match_input);
        rulePane.add(new JLabel("注解:"));
        commit_input.setColumns(38);
        rulePane.add(commit_input);
        return rulePane;
    }

    private JComponent createBtnPane(){
        JPanel btnPane = new JPanel(new FlowLayout(FlowLayout.CENTER));
        btn.setSize(10,10);
        btnPane.add(btn);
        return btnPane;
    }

    private void initListeners() {
        btn.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e)
            {
                if (!match_input.getText().isEmpty()){
                    rule.add(new Rule(cmb1.getSelectedIndex(),match_input.getText(),commit_input.getText()));
                    ruleTableMoudle.fireTableStructureChanged();//表格模型自动更新
                }
                dispose();//关闭打开的窗口
            }
        });
    }
}

    private class Output extends JPanel {
        private JSplitPane splitPane;
        public JTabbedPane mainTabs;

        public Output()
        {
            super(new BorderLayout());
            mainTabs = new JTabbedPane();
            initGUI();
        }

        private void initGUI(){
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            // table of log entries
            JScrollPane scrollPane = new JScrollPane(new Table(BurpExtender.this));
            splitPane.setLeftComponent(scrollPane);

            //结果展示分为3个标签页，分别是发现的link页、原请求页
            //link页
            jTextArea = new JTextArea();
            jTextArea.setText("");
            JScrollPane jScrollPane = new JScrollPane(jTextArea);

            //原请求页
            JTabbedPane tabs = new JTabbedPane();
            requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            tabs.addTab("Request", requestViewer.getComponent());
            tabs.addTab("Response", responseViewer.getComponent());

            mainTabs.add("嗅探到到URI",jScrollPane);
            mainTabs.add("原请求页",tabs);

            splitPane.setRightComponent(mainTabs);

            // init main ui
            this.add(splitPane);
        }
    }
}
