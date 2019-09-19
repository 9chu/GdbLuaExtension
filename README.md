# GDB Lua扩展

本扩展脚本用于在GDB中辅助进行Lua调试，脚本扩展了GDB对Lua类型的可视化展示，并扩展了GDB的表达式计算，使之能够对复杂的Lua数据结构进行访问，此外，该扩展脚本还提供了诸如堆栈展开、局部变量打印以及基于硬件断点的Lua断点功能。

本脚本适用于Lua5.3版本，并且要求被调试程序具备完整的Lua数据结构符号。

你可以通过下述命令来编译带有调试符号的Lua：

```bash
make linux MYCFLAGS=-g && sudo make install
```

## 使用

使用`source`指令在gdb中加载该扩展脚本。

```gdb
(gdb) source gdb-lua-ext.py
GDB Lua5.3 Extension
* To use this extension, you have to compile lua with debug symbols.
* Please see the document for more details.
```

## 可视化展示扩展

脚本扩充了GDB的Pretty Printer函数，使得可以在GDB中展示更加人类可读的Lua数据结构。

当前扩充了这些Lua底层数据结构的展示：

- TValue
- TString
- Table
- CClosure
- LClosure
- Udata
- Proto

通过GDB的`print`函数来快速查看各种值：

```gdb
(gdb) p ((lua_State*)0x63e048).top
$1 = (TValue *) 0x63e690 <lua_lclosure^> = {gc = (LClosure *) 0x657bf0 <lua_lclosure> = {proto = (Proto *) 0x662020 <lua_prototype> = {
      args = 0 (varargs), source = (TString *) 0x657ba0 <lua_string> "=stdin", linedefined = 0, 
      upval_0 = (TString *) 0x63f270 <lua_string> "_ENV"}, upval_1 = (TValue *) 0x6620d0 <lua_table^> 0x63e960}}
```

以上述用例为例，`TValue`为Lua中的值类型，可以表示一个值，也可以指向堆上的对象：

```
$1 = <TValue表示的Lua对象类型> Lua对象值
```

若指向的为GC对象，则会表达为：

```
$1 = <TValue表示的Lua对象类型> = {gc = ...}
```

其中，`...`为实际指向的`Table*`、`TString*`等底层数据结构的表示。

此外，如果被打印的值为`TValue*`类型，则会表示为：

```
(TValue *) TValue对象的地址 <TValue表示的Lua对象类型> Lua对象值
```

配合`set print pretty on`命令可以获得更好的展示效果。

## 快捷函数扩展

脚本将部分Lua的C API重新实现了一遍，使得可以在GDB中访问Lua对象而不影响被调试进程，这些函数亦可以用于对Core Dump的调试。

与Lua C API的最大不同在于，下列方法全部是直接操作的Lua底层数据结构，而不是针对Lua虚拟机的操作。这也是建立在不影响被调试程序的前提下进行。

- $lua_getglobalstate(lua_State L) -> global_State*

    从一个Lua虚拟机对象中取出全局状态对象。

- $lua_nilobject() -> TValue

    返回全局唯一的nil值的引用。

- $lua_index2value(lua_State L, int idx) -> TValue*

    将Lua虚拟机栈索引值转为对应的TValue对象。

- $lua_rawget(TValue* table|Table* table, TValue key) -> TValue*

    等同于Lua API的`lua_rawget`方法，用于在Table中取值。
    
    若不存在则返回`$lua_nilobject()`。

- $lua_rawgeti(TValue* table|Table* table, int idx) -> TValue*

    等同于Lua API的`lua_rawgeti`方法，用于在Table中取值。
    
    若不存在则返回`$lua_nilobject()`。

- $lua_rawgets(TValue* table|Table* table, string key) -> TValue*

    以字符串为Key从Table中取出对应的值。
    
    由于脚本不能像Lua代码那样操作虚拟机状态，该方法基于最原始的`O(n)`算法遍历整个Table来找到对应的值，因此比较慢。

- $lua_rawlen(TValue* v|Table* v) -> int

    等同于Lua API的`lua_rawlen`，用于获取Lua对象的大小。

- $lua_getcachedstring(lua_State L, string key) -> TString*

    在Lua虚拟机中搜索全局缓存的字符串key。若没有找到则返回0，否则返回对应的TString对象。

- $lua_getregistrytable(lua_State L) -> TValue*

    获取全局注册表对象。

- $lua_getglobaltable(lua_State L) -> TValue*

    获取全局表（即_ENV）对象。

- $lua_getstack(lua_State L, int idx) -> CallInfo*

    根据idx获取指定栈帧的调用记录对象。

- $lua_getlocal(lua_State L, int frame, int idx) -> TValue*

    在第frame个栈帧上获取第idx个局部变量。

- $lua_getlocalname(lua_State L, int frame, int idx) -> string

    在第frame个栈帧上获取第idx个局部变量的变量名。

- $lua_getmetatable(TValue* v) -> Table*

    获取指定对象的元表，若没有则返回0。

## 扩展指令

- glua_traceback [L]

    执行栈展开，打印调用栈。
    
    方法可选Lua虚拟机对象指针，若不提供，则获取当前栈上下文的`L`变量作为Lua虚拟机指针。

- glua_stackinfo [L [idx]]

    打印指定栈帧的所有上下文变量，包括Upvalue、局部变量和函数入参。
    
    方法可选Lua虚拟机对象指针，若不提供，则获取当前栈上下文的`L`变量作为Lua虚拟机指针。
    
    方法可选idx指定栈帧，若不填则默认为0，即栈顶。

- glua_objectinfo [L]

    遍历Lua虚拟机，统计所有对象的内存占用。
    
    方法可选Lua虚拟机对象指针，若不提供，则获取当前栈上下文的`L`变量作为Lua虚拟机指针。

- glua_break [L] filename line_number

    遍历Lua虚拟机，根据文件名来寻找Lua函数对象并在指定行号的字节码处下硬件断点。
    
    该方法为在GDB中调试Lua提供了一种可能，但因为基于硬件断点实现，因此至多下四个断点。
    
    方法可选Lua虚拟机对象指针，若不提供，则获取当前栈上下文的`L`变量作为Lua虚拟机指针。

- glua_breakr [L] regex line_number

    该方法类似于`glua_break`，然而接受一个正则表达式，用于匹配函数原型的`source`。
    
    方法可选Lua虚拟机对象指针，若不提供，则获取当前栈上下文的`L`变量作为Lua虚拟机指针。
