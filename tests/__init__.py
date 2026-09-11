"""PoP 的测试包。

这个（空）文件的作用只有一个：让 ``tests`` 成为一个**常规包**，从而
``python3 -m unittest discover -s tests -t .`` 能用 —— 没有它，``tests`` 只是
命名空间目录，``unittest`` 的发现器会以 "Start directory is not importable"
直接退出。

测试模块自己不依赖包内相对导入（各自把仓库根塞进 ``sys.path``），所以
``python3 -m unittest tests.test_dsl`` 与发现式运行两种方式都成立。
"""
