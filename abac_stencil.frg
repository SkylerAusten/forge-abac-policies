#lang forge/domains/abac

// All these policies work over three variables:
// s: the subject (i.e., the user making the request);
// a: the action (i.e., what kind of request they are making); and
// r: the resource (i.e., what is being requested).

// This policy defines who can read files in our fictional cloud system.
// Each rule is checked in order, so the first rule that matches applies.
policy original
  // Administrators can read and write anything
  permit if: s is admin, a is read.
  permit if: s is admin, a is write.
  // Files being audited can't be changed by customers
  deny   if: a is write, r is file, r is under-audit.
  // Customers have full access to files they own
  permit if: s is customer, a is read, s is owner-of r.
  permit if: s is customer, a is write, s is owner-of r.
end;

// Sometimes audits of the data need to be performed. At first, our company is small,
// and audits are facilitated by an admin who freezes the file and does the audit themselves.
// Once the company grows, a new type of employee -- the accountant -- is created. 
// (Application and removal of the auditing flag is outside the scope of this assignment!)
// Let's modify the above policy to handle auditors.

policy modified
  // Administrators can read and write anything
  permit if: s is admin, a is read.
  permit if: s is admin, a is write.
  
  // (EDITED Feb 5 2023: note this was the unintentional rule)
  // Files being audited can't be changed by customers
  //deny   if: a is write, r is file, r is under-audit.
  deny if: s is customer, a is write, r is file, r is under-audit.

  // Customers have full access to files they own
  permit if: s is customer, a is read, s is owner-of r.
  permit if: s is customer, a is write, s is owner-of r.

  //////////////////// New rules below this point /////////////////////

  // Once completing training, accountants can read and write to files under audit
  deny   if: s is in-training.
  permit if: s is accountant, a is read, r is under-audit.
  permit if: s is accountant, a is write, r is under-audit.    
end;

// First, let's ask Forge to tell us about differences between the policies:
//compare original modified;
// When you run this, you should see a report that says something like:
//   Found example request involving...
//   a subject <s> that is:  Accountant, Employee
//   an action <a> that is:  Read
//   a resource <r> that is: File
//   Also,
//     <r> is Audit
// This looks good! But it's only one example. 
// Is it possible for any changes to impact non-accountants?
compare original modified where s is not accountant;
// No -- that's great!

// YOUR TASK: (EDITED FEB 5, 2023) 
// The "deny if" rule in the policy above prevents customers from modifying 
//   their own files while those files are being audited. That's by design. 
//   But is it possible that the rule has a broader effect than intended? 
//   
//   (1) Consider how that "deny if" rule could impact the new rules we added 
//   to allow accountants to edit files they are auditing. Why is the 
//   "deny if" rule likely to impact accountants as well as customers?
//   This command might help:

// The rule does not distinguish between user roles beyond the action being taken and the status of the file. 
// This means the rule could inadvertently apply to accountants as well as customers, 
// meaning accountants couldn't modify files under audit.
// This occurs because the rule applies to any "write" action on a file under audit 
// without considering the actor's role.

compare original modified where s is accountant, a is write, r is under-audit;

//   The tool reports no difference! Uh oh...

//   (2) Modify the rule to apply only to *customers*. 
// deny if: s is customer, a is write, r is file, r is under-audit.
//   (3) Re-run the above "compare" command. You should see some requests are 
//       now handled differently. 
// Yep!

