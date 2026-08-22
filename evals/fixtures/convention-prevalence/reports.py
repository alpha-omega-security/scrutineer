from store import STATUS_ACTIVE, STATUS_CLOSED, STATUS_TRIAL, query


def active_accounts():
    return query("SELECT id FROM accounts WHERE status = '%s'" % STATUS_ACTIVE)


def closed_accounts():
    return query("SELECT id FROM accounts WHERE status = '%s'" % STATUS_CLOSED)


def trial_accounts():
    return query("SELECT id FROM accounts WHERE status = '%s'" % STATUS_TRIAL)


def active_invoices():
    return query("SELECT id FROM invoices WHERE status = '%s'" % STATUS_ACTIVE)


def closed_invoices():
    return query("SELECT id FROM invoices WHERE status = '%s'" % STATUS_CLOSED)


def trial_invoices():
    return query("SELECT id FROM invoices WHERE status = '%s'" % STATUS_TRIAL)


def active_seats():
    return query("SELECT id FROM seats WHERE status = '%s'" % STATUS_ACTIVE)


def closed_seats():
    return query("SELECT id FROM seats WHERE status = '%s'" % STATUS_CLOSED)
