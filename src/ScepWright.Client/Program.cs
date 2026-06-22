using ScepWright.Client;
using ScepWright.Core.Storage;

string? data_dir_flag;
string root;

data_dir_flag = GetFlag(args, "--data-dir");
root = DataRoot.Resolve(data_dir_flag);
PassphrasePrompt.Interactive = true;   // real CLI session: allow hidden prompt / stdin passphrase
return CommandRouter.Run(args, root, System.Console.Out);

static string? GetFlag(string[] args, string name) {
    int i;

    for (i = 0; i < args.Length - 1; i++) {
        if (args[i] == name) { return args[i + 1]; }
    }
    return null;
}
