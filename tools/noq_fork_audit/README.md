# NOQ fork intelligence

This directory implements a read-only fork and branch auditor for n0-computer/noq. It never executes fork code. Scheduled runs begin only when the GitHub Actions workflow is present on the default branch. Reports are uploaded as workflow artifacts; candidate priorities require manual review.
