using ScepWright.Dispatcher;

ScepWright.Client.PassphrasePrompt.Interactive = true;   // real CLI session: allow hidden prompt / stdin passphrase
ScepWright.Server.Host.CaKeyPassphrase.Interactive = true;   // same for the scepca/scepwright-server CA key passphrase
return DispatcherCli.Run(args, System.Console.Out);
