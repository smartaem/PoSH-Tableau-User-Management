# PoSH-Tableau-User-Management
Tableau User management with Powershell

This script is used to manage Tableau users based on an ldap group.

To run this script, modify the "config/groupmapping.config" json configuration file to fit your environment 


Everything on the json configuration file is self-explanatory, but I will call out "defaultuser". During the delettion of a user, if the
user owns assets, those assets will need to reassigned to a different users before a successful deletion can occur. The assets owned by the 
user being deleted will be reassigned to the "defaultuser"



