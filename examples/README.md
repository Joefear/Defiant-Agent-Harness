# Examples

Three workspaces mirroring the demo workflows in the build document. Each is a
folder plus the policy pack it runs under; the scenarios themselves live in the
mock adapter's `SCRIPTS` so they stay deterministic and testable.

    usaveprocessing/     merchant statement review   --policy merchant_services
    legal_intake/        attorney intake             --policy legal_intake
    content_publishing/  drafting and publishing     default pack

Run one:

    cd examples/usaveprocessing
    dah demo prohibited_claim --policy merchant_services
    dah demo send_email --policy merchant_services --auto-approve
    dah history
    dah verify
