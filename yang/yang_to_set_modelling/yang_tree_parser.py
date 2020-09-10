import lxml
import xmltodict

yin_file = open("firewall.yin","r").read()
parse = xmltodict.parse(yin_file)

mod_name = parse["module"]["@name"]
prefix = parse["module"]["prefix"]["@value"]
base = "set {}:{}".format(mod_name,prefix)

#def parse_leaf():

#def parse_container():

for i in parse["module"]:
   if i == "container":
       c_name = parse["module"]["container"]["@name"]
       for j in parse["module"]["container"]:
           if j == "leaf":
              l_name = parse["module"]["container"]["leaf"]["@name"]
              final = base +" "+ c_name+" " + l_name+ " { user defined value }"
              print(final)
