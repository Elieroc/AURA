"""Non-régression : le garde-fou des répertoires système est-il contournable ?

L'exclusion des binaires système repose sur une comparaison de PRÉFIXE
(`_chemin_win_hors_systeme`). Une comparaison de préfixe ne vaut que sur un
chemin canonique : toute autre écriture du même fichier passe à côté, alors que
l'API Windows, elle, résout parfaitement le chemin en bout de chaîne.

Ce que ces tests protègent, concrètement : un exercice purple-team a produit
26 ordres de quarantaine sur des binaires signés de System32 d'un contrôleur de
domaine. La mise en quarantaine DÉPLACE le fichier puis lui applique un deny
total — sur un binaire de service, l'hôte est hors d'état, et c'est le SOC qui
l'a fait.
"""

from soc_agent.mitigate import (_chemin_win_hors_systeme, _chemin_win_suspect,
                                _norm_chemin_win, _win_fichiers_suspects)

LSASS = r"C:\Windows\System32\lsass.exe"


def test_norm_replie_les_antislashes_doubles():
    """Le JSON de l'eventchannel double les antislashes ; sans repli, la
    comparaison au répertoire système n'est jamais vraie."""
    assert _norm_chemin_win(r"C:\\Windows\\System32\\cmd.exe") == \
        r"C:\Windows\System32\cmd.exe"


def test_norm_retire_le_prefixe_de_chemin_long():
    r"""`\\?\` et `\??\` designent le meme fichier sans commencer par c:\windows."""
    assert _norm_chemin_win(r"\\?\C:\Windows\System32\lsass.exe") == LSASS
    assert _norm_chemin_win(r"\??\C:\Windows\System32\lsass.exe") == LSASS


def test_norm_resout_les_remontees_de_repertoire():
    assert _norm_chemin_win(
        r"C:\Users\Public\..\..\Windows\System32\lsass.exe") == LSASS


def test_norm_preserve_les_chemins_unc():
    """La forme longue UNC redevient un UNC ordinaire, pas un chemin local."""
    assert _norm_chemin_win(r"\\?\UNC\srv\partage\implant.exe") == \
        r"\\srv\partage\implant.exe"


def test_system32_reste_protege_quelle_que_soit_l_ecriture():
    """LE test. Chacune de ces formes désigne lsass.exe et était acceptée comme
    « implant déposé hors système » avant canonicalisation."""
    for variante in (
        LSASS,
        r"\\?\C:\Windows\System32\lsass.exe",
        r"\??\C:\Windows\System32\lsass.exe",
        r"C:\Users\Public\..\..\Windows\System32\lsass.exe",
        r"C:\\Windows\\System32\\lsass.exe",
        r"c:\windows\system32\lsass.exe",
    ):
        assert not _chemin_win_hors_systeme(variante), variante
        assert not _chemin_win_suspect(variante), variante


def test_chemin_non_resolvable_refuse():
    """Une remontée au-delà de la racine ne désigne rien de nommable : on
    n'agit pas plutôt que de deviner."""
    assert not _chemin_win_hors_systeme(r"..\..\evil.exe")
    assert not _chemin_win_hors_systeme("")


def test_un_vrai_implant_reste_ciblable():
    """La canonicalisation ne doit pas rendre le garde-fou aveugle : un binaire
    réellement déposé hors système reste une cible."""
    assert _chemin_win_suspect(r"C:\Users\Public\evil.exe")
    assert _chemin_win_suspect(r"\\?\C:\Users\Public\evil.exe")
    assert _chemin_win_hors_systeme(r"C:\ProgramData\payload.dll")


def test_extraction_normalise_les_cibles():
    """Les cibles extraites d'une alerte sortent sous forme canonique : le
    script AR compare et agit sur la même chaîne que celle stockée en base."""
    alerte = {"agent_id": "001", "entity": None, "raw": {"data": {"win": {
        "eventdata": {"image": r"\\?\C:\Users\Public\evil.exe"}}}}}
    assert _win_fichiers_suspects([alerte]) == {r"C:\Users\Public\evil.exe"}


def test_extraction_ecarte_system32_deguise():
    """Même alerte, mais l'attaquant a écrit le chemin de lsass en forme longue."""
    alerte = {"agent_id": "001", "entity": None, "raw": {"data": {"win": {
        "eventdata": {"image": r"\\?\C:\Windows\System32\lsass.exe"}}}}}
    assert _win_fichiers_suspects([alerte]) == set()
