# GDB Lua��չ

����չ�ű�������GDB�и�������Lua���ԣ��ű���չ��GDB��Lua���͵Ŀ��ӻ�չʾ������չ��GDB�ı��ʽ���㣬ʹ֮�ܹ��Ը��ӵ�Lua���ݽṹ���з��ʣ����⣬����չ�ű����ṩ�������ջչ�����ֲ�������ӡ�Լ�����Ӳ���ϵ��Lua�ϵ㹦�ܡ�

���ű�������Lua5.3�汾������Ҫ�󱻵��Գ���߱�������Lua���ݽṹ���š�

�����ͨ������������������е��Է��ŵ�Lua��

```bash
make linux MYCFLAGS=-g && sudo make install
```

## ʹ��

ʹ��`source`ָ����gdb�м��ظ���չ�ű���

```gdb
(gdb) source gdb-lua-ext.py
GDB Lua5.3 Extension
* To use this extension, you have to compile lua with debug symbols.
* Please see the document for more details.
```

## ���ӻ�չʾ��չ

�ű�������GDB��Pretty Printer������ʹ�ÿ�����GDB��չʾ��������ɶ���Lua���ݽṹ��

��ǰ��������ЩLua�ײ����ݽṹ��չʾ��

- TValue
- TString
- Table
- CClosure
- LClosure
- Udata
- Proto

ͨ��GDB��`print`���������ٲ鿴����ֵ��

```gdb
(gdb) p ((lua_State*)0x63e048).top
$1 = (TValue *) 0x63e690 <lua_lclosure^> = {gc = (LClosure *) 0x657bf0 <lua_lclosure> = {proto = (Proto *) 0x662020 <lua_prototype> = {
      args = 0 (varargs), source = (TString *) 0x657ba0 <lua_string> "=stdin", linedefined = 0, 
      upval_0 = (TString *) 0x63f270 <lua_string> "_ENV"}, upval_1 = (TValue *) 0x6620d0 <lua_table^> 0x63e960}}
```

����������Ϊ����`TValue`ΪLua�е�ֵ���ͣ����Ա�ʾһ��ֵ��Ҳ����ָ����ϵĶ���

```
$1 = <TValue��ʾ��Lua��������> Lua����ֵ
```

��ָ���ΪGC���������Ϊ��

```
$1 = <TValue��ʾ��Lua��������> = {gc = ...}
```

���У�`...`Ϊʵ��ָ���`Table*`��`TString*`�ȵײ����ݽṹ�ı�ʾ��

���⣬�������ӡ��ֵΪ`TValue*`���ͣ�����ʾΪ��

```
(TValue *) TValue����ĵ�ַ <TValue��ʾ��Lua��������> Lua����ֵ
```

���`set print pretty on`������Ի�ø��õ�չʾЧ����

## ��ݺ�����չ

�ű�������Lua��C API����ʵ����һ�飬ʹ�ÿ�����GDB�з���Lua�������Ӱ�챻���Խ��̣���Щ������������ڶ�Core Dump�ĵ��ԡ�

��Lua C API�����ͬ���ڣ����з���ȫ����ֱ�Ӳ�����Lua�ײ����ݽṹ�����������Lua������Ĳ�������Ҳ�ǽ����ڲ�Ӱ�챻���Գ����ǰ���½��С�

- $lua_getglobalstate(lua_State L) -> global_State*

    ��һ��Lua�����������ȡ��ȫ��״̬����

- $lua_nilobject() -> TValue

    ����ȫ��Ψһ��nilֵ�����á�

- $lua_index2value(lua_State L, int idx) -> TValue*

    ��Lua�����ջ����ֵתΪ��Ӧ��TValue����

- $lua_rawget(TValue* table|Table* table, TValue key) -> TValue*

    ��ͬ��Lua API��`lua_rawget`������������Table��ȡֵ��
    
    ���������򷵻�`$lua_nilobject()`��

- $lua_rawgeti(TValue* table|Table* table, int idx) -> TValue*

    ��ͬ��Lua API��`lua_rawgeti`������������Table��ȡֵ��
    
    ���������򷵻�`$lua_nilobject()`��

- $lua_rawgets(TValue* table|Table* table, string key) -> TValue*

    ���ַ���ΪKey��Table��ȡ����Ӧ��ֵ��
    
    ���ڽű�������Lua�����������������״̬���÷���������ԭʼ��`O(n)`�㷨��������Table���ҵ���Ӧ��ֵ����˱Ƚ�����

- $lua_rawlen(TValue* v|Table* v) -> int

    ��ͬ��Lua API��`lua_rawlen`�����ڻ�ȡLua����Ĵ�С��

- $lua_getcachedstring(lua_State L, string key) -> TString*

    ��Lua�����������ȫ�ֻ�����ַ���key����û���ҵ��򷵻�0�����򷵻ض�Ӧ��TString����

- $lua_getregistrytable(lua_State L) -> TValue*

    ��ȡȫ��ע������

- $lua_getglobaltable(lua_State L) -> TValue*

    ��ȡȫ�ֱ���_ENV������

- $lua_getstack(lua_State L, int idx) -> CallInfo*

    ����idx��ȡָ��ջ֡�ĵ��ü�¼����

- $lua_getlocal(lua_State L, int frame, int idx) -> TValue*

    �ڵ�frame��ջ֡�ϻ�ȡ��idx���ֲ�������

- $lua_getlocalname(lua_State L, int frame, int idx) -> string

    �ڵ�frame��ջ֡�ϻ�ȡ��idx���ֲ������ı�������

- $lua_getmetatable(TValue* v) -> Table*

    ��ȡָ�������Ԫ����û���򷵻�0��

## ��չָ��

- glua_traceback [L]

    ִ��ջչ������ӡ����ջ��
    
    ������ѡLua���������ָ�룬�����ṩ�����ȡ��ǰջ�����ĵ�`L`������ΪLua�����ָ�롣

- glua_stackinfo [L [idx]]

    ��ӡָ��ջ֡�����������ı���������Upvalue���ֲ������ͺ�����Ρ�
    
    ������ѡLua���������ָ�룬�����ṩ�����ȡ��ǰջ�����ĵ�`L`������ΪLua�����ָ�롣
    
    ������ѡidxָ��ջ֡����������Ĭ��Ϊ0����ջ����

- glua_objectinfo [L]

    ����Lua�������ͳ�����ж�����ڴ�ռ�á�
    
    ������ѡLua���������ָ�룬�����ṩ�����ȡ��ǰջ�����ĵ�`L`������ΪLua�����ָ�롣

- glua_break [L] filename line_number

    ����Lua������������ļ�����Ѱ��Lua����������ָ���кŵ��ֽ��봦��Ӳ���ϵ㡣
    
    �÷���Ϊ��GDB�е���Lua�ṩ��һ�ֿ��ܣ�����Ϊ����Ӳ���ϵ�ʵ�֣�����������ĸ��ϵ㡣
    
    ������ѡLua���������ָ�룬�����ṩ�����ȡ��ǰջ�����ĵ�`L`������ΪLua�����ָ�롣

- glua_breakr [L] regex line_number

    �÷���������`glua_break`��Ȼ������һ��������ʽ������ƥ�亯��ԭ�͵�`source`��
    
    ������ѡLua���������ָ�룬�����ṩ�����ȡ��ǰջ�����ĵ�`L`������ΪLua�����ָ�롣
