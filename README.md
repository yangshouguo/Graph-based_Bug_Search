redo the paper 'Scalable Graph-based Bug Search for Firmware Images'
and improve it's method if i can

##Before you use
you need change the variable idapath in file PYAPI_Featureobbinary.py line 5
to the ida text interface in your system
like : idapath = 'idal64'

### 使用pip 给IDAPython安装python库

安装networkx python库

    pip install setuptools --target=/home/ysg/ida-6.95/python  #your ida python directory
    pip install networkx --target=/home/ysg/ida-6.95/python

--target 后面的值是你的IDAPython所在目录



## you can use like this
* python PYAPI_Featureofbinary.py -h to see help of script

or

* idat64 -S "Feature_Of_Binary.py saved_file [func_name]" nbsmtp
