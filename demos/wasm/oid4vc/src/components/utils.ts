import { DIDKey, InMemKms, KeyMetadata, KeyType, UniversalDIDResolver } from "@equs/equs-sdk";

export type DidAndKeyMetadata = {
  did: string;
  keyMetadata: KeyMetadata;
};

export async function createDidAndKeyMetadata(kms: InMemKms): Promise<DidAndKeyMetadata> {
  const keyId = await kms.create(KeyType.P256);
  const keyHandle = await kms.get(keyId);
  const didKey = new DIDKey();

  const did = didKey.generate(keyHandle);

  const universalDidResolver = new UniversalDIDResolver();

  const vm = await universalDidResolver.resolveVerificationMethod(did);

  if (!vm) {
    throw new Error("DID Verification Method is undefined");
  }

  const keyMetadata: KeyMetadata = {
    didUrl: vm.id,
    kid: keyId,
  };

  return { did, keyMetadata };
}

export async function createInputContainer(
  message: string,
  url: string,
): Promise<{
  container: HTMLElement;
  input: HTMLInputElement;
  button: HTMLButtonElement;
}> {
  const container = document.getElementById("inputContainer") ?? document.createElement("div");
  container.id = "inputContainer";
  document.body.appendChild(container);

  const label = document.createElement("p");
  label.innerText = message;
  container.appendChild(label);

  const link = document.createElement("a");
  link.innerText = "link";
  link.href = url;
  link.target = "_blank";
  container.appendChild(link);

  const input = document.createElement("input");
  input.type = "text";
  input.id = "userInput";
  input.placeholder = "Input";
  container.appendChild(input);

  const buttonContainer = document.createElement("div");

  const button = document.createElement("button");
  button.innerText = "Send";

  buttonContainer.appendChild(button);
  container.appendChild(buttonContainer);

  return { container, input, button };
}

export async function removeContainer(container: HTMLElement): Promise<void> {
  if (container.parentNode) container.parentNode.removeChild(container);
}

export async function readFromBrowserInput(params: {
  input: HTMLInputElement;
  button: HTMLButtonElement;
}): Promise<string> {
  return new Promise((resolve) => {
    params.button.onclick = () => {
      resolve(params.input.value);
    };
  });
}
