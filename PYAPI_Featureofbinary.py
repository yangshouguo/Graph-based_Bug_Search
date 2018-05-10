#encoding=utf-8
#无需学会idapython 的使用，直接调用该类下的接口即可获得函数

#系统ida所在的路径
idapath = 'idat64'
import os,sys,time,commands,json
import argparse

parse = argparse.ArgumentParser()

class getFeature:
    def __init__(self, binarypath):
        self._bin = binarypath
        self._tmpfile = binarypath + str(time.time()) + '.json'
        pass

    #read json file to get features
    def _ReadFeatures(self):
        with open(self._tmpfile,'r') as f:
            for line in f.readlines():
                # print line
                x = json.loads(line)
                yield x

    def _del_tmpfile(self):
        os.remove(self._tmpfile)

    def get_Feature_all(self):
        return self.get_Feature_Function('')
        pass

    def get_Feature_Function(self, func_name):

        cmd = "TVHEADLESS=1 %s -A -S'Feature_Of_Binary.py %s %s' %s" % (idapath, self._tmpfile, func_name, self._bin)
        s,o = commands.getstatusoutput(cmd)

        if s!=0 :
            print s,o
            return None

        features = list(self._ReadFeatures())
        self._del_tmpfile()
        return features

def test(args):

    binary_path = args.binaryfile
    # generate ida database file
    if args.b:
        database = '.i64'
        # from utils import generate_i64
        cmd = 'TVHEADLESS=1 %s -B  %s' % (idapath, binary_path)
        # database = generate_i64(binary_path, binary_path + '.i64')
        s,o = commands.getstatusoutput(cmd)
        if s != 0:
            print s,o
            return
        binary_path += '.i64'

    func_name = ''
    out_file = ''
    if args.f:
        func_name = args.f
    if args.o:
        out_file = args.o

    gf = getFeature(binary_path)
    feature = gf.get_Feature_Function(func_name)

    if len(out_file) > 0:
        with open(out_file, 'w') as f:
            json.dump(feature, f)
    else:
        for x in feature:
            print x


if __name__ == '__main__':
    parse.add_argument('binaryfile', help='file to be analysed')
    parse.add_argument('-f', help='function name to be handled ')
    parse.add_argument('-b', help='file to be analysed is binary file , default is ida database file', action = 'store_true' , default=False)
    parse.add_argument('-o', help='output filename')
    args = parse.parse_args()
    test(args)


