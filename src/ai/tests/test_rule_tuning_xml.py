"""Non-régression : une valeur d'alerte ne doit pas pouvoir écrire du XML.

`rule_tuning` génère des fichiers de règles Wazuh à partir de signatures de faux
positifs. Ces signatures contiennent des valeurs écrites par les machines
surveillées — `url` en particulier, qui est intégralement choisie par le client
qui frappe le reverse proxy, et qui est le premier contributeur de faux positifs
de la plateforme.

Les CONDITIONS de la règle étaient déjà échappées et ancrées. Le commentaire
d'en-tête, lui, interpolait les valeurs brutes : un `-->` le refermait et le
reste devenait du XML chargé par le manager au redémarrage suivant — soit
l'injection d'une règle arbitraire dans le moteur de détection, par exemple un
`level="0"` qui éteint silencieusement une famille de détections.

Note : `saxutils.escape` ne suffit PAS ici. Il ne traite pas `--`, qui est
illégal dans un commentaire XML et suffit à en sortir.
"""

from xml.etree import ElementTree

from soc_agent.rule_tuning import _commentable, construire_xml

# Charge utile : referme le commentaire, injecte une regle qui neutralise une
# detection, puis rouvre un commentaire pour que le fichier reste bien forme.
CHARGE = ('/x?a=--><rule id="100999" level="0"><if_sid>31100</if_sid>'
          '<description>neutralise</description></rule><!--')


def _construire(signature):
    return construire_xml(rule_id=101000, parent="31100", niveau=5,
                          signature=signature, raw={}, n_fp=3,
                          incidents=[1, 2, 3])


def test_commentable_neutralise_la_fermeture_de_commentaire():
    rendu = _commentable(CHARGE)
    assert "-->" not in rendu
    assert "<" not in rendu and ">" not in rendu


def test_commentable_neutralise_les_doubles_tirets_isoles():
    """`--` seul suffit : un commentaire XML ne peut pas en contenir."""
    assert "--" not in _commentable("valeur--avec--tirets")


def test_commentable_borne_la_longueur():
    assert len(_commentable("A" * 5000)) == 200
    assert len(_commentable("A" * 5000, 400)) == 400


def test_url_hostile_ne_produit_pas_de_regle_supplementaire():
    """LE test : la charge ne doit pas devenir une <rule> chargée par le manager."""
    xml = _construire({"rule_id": "31100", "url": CHARGE})
    assert xml is not None

    racine = ElementTree.fromstring(xml)
    regles = racine.findall("rule")
    assert len(regles) == 1, "une regle injectee s'est ajoutee au fichier"
    assert regles[0].get("id") == "101000"
    assert regles[0].get("level") == "5"
    # Le texte de la charge survit sous forme inerte (chiffres, mots) dans le
    # commentaire et dans la condition — c'est normal et voulu, c'est la trace
    # de ce qui a été exonéré. Ce qui compte est qu'aucun balisage ne subsiste :
    # ni ouverture d'élément, ni fermeture de commentaire.
    assert "<rule id=\"100999\"" not in xml
    entete = xml.split("-->", 1)[0]
    assert "<" not in entete[4:] and ">" not in entete[4:]


def test_le_xml_genere_reste_bien_forme_sur_valeur_hostile():
    """Une charge qui casserait le XML ferait échouer le chargement du ruleset
    entier : le manager refuserait de démarrer, `_redemarrer` échouerait, et le
    lot serait retiré au prix d'un second redémarrage. La génération doit donc
    produire un document valide — ou refuser."""
    for valeur in (CHARGE, "a--b", "<!--", "-->", "]]>", "&amp;", "'\"<>"):
        xml = _construire({"rule_id": "31100", "url": valeur})
        assert xml is not None, valeur
        ElementTree.fromstring(xml)   # lève si mal formé


def test_caractere_interdit_par_xml_refuse_la_signature():
    """XML 1.0 ne peut pas porter un caractère de contrôle, même échappé. Une
    telle signature n'est pas traduisible en règle : on refuse plutôt que
    d'écrire un fichier que le moteur ne saura pas charger."""
    assert _construire({"rule_id": "31100", "url": "/x\x00nul"}) is None
    assert _construire({"rule_id": "31100", "command": "a\x07b"}) is None


def test_la_condition_reste_ancree_et_echappee():
    """La neutralisation du commentaire ne doit pas relâcher la condition :
    elle reste ancrée sur la valeur exacte, échappée pour pcre2. `url` passe par
    l'option dédiée `<url>` et non par un `<field>` générique."""
    xml = _construire({"rule_id": "31100", "url": "/build.sh"})
    champ = ElementTree.fromstring(xml).find("rule/url")
    assert champ.get("type") == "pcre2"
    assert champ.text == r"^/build\.sh$"


def test_signature_canonique_relisible_pour_l_idempotence():
    """Le commentaire porte l'état : la signature écrite doit être exactement
    celle que `_signatures_deja_traitees` relira, sinon la règle est régénérée
    à chaque cycle — un redémarrage du manager par passage."""
    signature = {"rule_id": "31100", "url": CHARGE}
    xml = _construire(signature)
    from soc_agent.whitelist import _canonique
    attendu = _commentable(_canonique(signature), 400)
    assert f"signature-canonique: {attendu}" in xml
