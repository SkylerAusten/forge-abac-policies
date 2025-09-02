# Social Media Account Control Policy
## Natural Language Context
On a social media platform, users may share posts with different groups: their friends, their family, or their coworkers.

## Natural Language Policy
The user wants to share a post with friends and family. Coworkers must not see this post unless they are also family.

# Spy Ring (Different Context)
## Natural Language Context
In a spy ring, spies may share intelligence reports with different groups: other spies, their supervisors, and government officials.

## Natural Language Policy
The spy wants to share an intelligence report with other spies and their supervisors. Government officials must not see this intelligence report unless they are also a supervisor.

# Three Roles + "Special Individual" (Student + TA)
## Natural Language Context
At a university, students may submit assignments, teaching assistants (TAs) may grade assignments, and professors may grade assignments and assign final grades.

## Natural Language Policy
If a person is both a student and a TA, they may grade other students' assignments but must not grade their own.

# Temporal Access Control (Building Access) 
## Natural Language Context
In an office building, employees, security staff, and visitors may enter the company building.

## Natural Language Policy
Employees may be in the building during working hours and must not be in the building outside of working hours. Security may be in the building at any time. Visitors must have a guest pass to enter, and must not be in the building outside of working hours.

# Phased Access (Job Applications)
## Natural Language Context
In a job application system there are applicants, application reviewers, and a hiring manager. There is an application deadline, a review deadline, and a hiring deadline. Applicants may submit applications.  Reviewers may read applications and submit reviews.  The hiring manager may read applications and their reviews and may make a hiring decision.

## Natural Language Policy
Applicants MUST be permitted to submit one or more applications before the application deadline. 
Applicants MUST NOT be permitted to submit applications after the application deadline.
Reviewers MUST be permitted to read applications after the application deadline has passed.
Reviewers MUST NOT be permitted to read applications before the application deadline.
Reviewers MUST be permitted to submit reviews after the application deadline and before the review deadline.
Reviewers MUST NOT be permitted to submit reviews outside of that timeframe.
Hiring Managers MUST be permitted to read applications and reviews after the review deadline has passed.
Hiring Managers MUST NOT be permitted to read applications and reviews before the review deadline.
Hiring Managers MAY extend offers after the review deadline but before the hiring deadline.
Hiring Managers MUST NOT extend offers before the review deadline.
Hiring Managers MUST NOT extend offers after the review deadline.
An applicant must not be extended more than one offer.