!/bin/sh
# 删除服务器.m2中的ipsec
rm -rf ~/.m2/repository/org/opendaylight/ipsec
# 删除odl的system下的ipsec
rm -rf ~/Liu/Graduation/OpenDaylight/distribution-karaf-0.4.2-Beryllium-SR2/system/org/opendaylight/ipsec
# 
mkdir  ~/Liu/Graduation/OpenDaylight/distribution-karaf-0.4.2-Beryllium-SR2/system/org/opendaylight/ipsec
# 删除缓存
rm -r ~/Liu/Graduation/OpenDaylight/distribution-karaf-0.4.2-Beryllium-SR2/data
#
mkdir ~/Liu/Graduation/OpenDaylight/distribution-karaf-0.4.2-Beryllium-SR2/data
# 编译新代码
cd ~/Liu/Graduation/ODLModule/odl-ipsec/api
maven clean install
cd ~/Liu/Graduation/ODLModule/odl-ipsec/impl
maven clean install -D skipTests
cd ~/Liu/Graduation/ODLModule/odl-ipsec
maven clean install -D skipTests
# 将.m2的ipsec拷贝到控制器
cp -r ~/.m2/repository/org/opendaylight/ipsec/* ~/Liu/Graduation/OpenDaylight/distribution-karaf-0.4.2-Beryllium-SR2/system/org/opendaylight/ipsec
# 开启控制器
cd ~/Liu/Graduation/OpenDaylight/distribution-karaf-0.4.2-Beryllium-SR2
./bin/karaf

