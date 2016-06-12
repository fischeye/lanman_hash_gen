# Lan Manager Hash Generator

Hier kommt ein komplettes Script zum generieren von Lan Manager Hash Codes. Windows verwendet diese Methode zum Speichern der Benutzer-Kennwörter. Die aktuelleren Version verwenden jedoch einen etwas weiterentwickelten Algorythmus, welcher jedoch auch nicht wesentlich schwieriger ist nachzustellen.

Die Benutzeraccounts und ihre Passwort-Hashes befinden sich an denn folgenden Orten:

Benutzer-Registrykeys:

HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users

Zuordnung Benutzername zu Benutzer-Registrykey:

HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names

Beispielsweise befindet sicht unter Users ein Key 000001F4. Unter dem Key Names findet man einen Administrator mit dem Verweis auf diesen Key. Sprich: Administrator = 000001F4. Unter diesem Key befindet sich der Passwort-Hash.
