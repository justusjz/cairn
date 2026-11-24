// An identity policy's editor: the visual builder or the JSON (see
// `PolicyBuilder`, which also offers levels of access to a bucket). Used for
// managed policies (the Policies page) and users', groups' and roles' inline
// ones alike.

import { PolicyDocumentEditor } from "./PolicyBuilder";

/** An empty identity policy. */
export const EMPTY = `{
  "Version": "2012-10-17",
  "Statement": []
}`;

export function PolicyEditor(props: {
  document: string;
  setDocument: (d: string) => void;
  buckets: string[];
  readOnly?: boolean;
  disabled?: boolean;
}) {
  return (
    <>
      <PolicyDocumentEditor
        kind="identity"
        label="Policy document"
        document={props.document}
        setDocument={props.setDocument}
        buckets={props.buckets}
        readOnly={props.readOnly}
        disabled={props.disabled}
      />
      <p class="subtle small">
        IAM's policy language, as an identity policy: no Principal; Resource names buckets (
        <span class="mono">arn:aws:s3:::bucket</span>) and objects (<span class="mono">arn:aws:s3:::bucket/key</span>).
      </p>
    </>
  );
}
