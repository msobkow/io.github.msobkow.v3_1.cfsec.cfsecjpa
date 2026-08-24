// Description: Java 25 JPA implementation of SecUserPassword history objects

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import jakarta.transaction.Transactional;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *  CFSecJpaSecUserPasswordH provides history objects matching the CFSecSecUserPassword change history.
 *	Note that because all indexes are historical with multiple instances of history records, the only key that can be unique is the primary key of a history table.
 */
public class CFSecJpaSecUserPasswordH
    implements ICFSecSecUserPasswordH, Comparable<Object>, Serializable
{
	@AttributeOverrides({
		@AttributeOverride(name="auditClusterId", column = @Column( name="auditClusterId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) ),
		@AttributeOverride(name="auditStamp", column = @Column( name="auditStamp", nullable=false ) ),
		@AttributeOverride(name="auditAction", column = @Column( name="auditAction", nullable=false ) ),
		@AttributeOverride(name="requiredRevision", column = @Column( name="requiredRevision", nullable=false ) ),
		@AttributeOverride(name="auditSessionId", column = @Column( name="auditSessionId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) ),
		@AttributeOverride(name="SecUserId", column = @Column( name="SecUserId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) )
	})
    protected CFSecJpaSecUserPasswordHPKey pkey;
	protected $implIJavaAtomType$ requiredPWSetStamp;
	protected $implIJavaAtomType$ requiredPasswordHash;

    public CFSecJpaSecUserPasswordH() {
            // The primary key member attributes are initialized on construction
            pkey = new CFSecJpaSecUserPasswordHPKey();
		requiredPWSetStamp = CFLibXmlUtil.parseTimestamp("2020-01-01T00:00:00");
    }

    @Override
    public int getClassCode() {
            return( ICFSecSecUserPassword.CLASS_CODE );
    }

    @Override
    public ICFSecSecUserPasswordHPKey getPKey() {
        return( pkey );
    }

    @Override
    public void setPKey( ICFSecSecUserPasswordHPKey pkey ) {
        if (pkey != null) {
            if (pkey instanceof CFSecJpaSecUserPasswordHPKey) {
                this.pkey = (CFSecJpaSecUserPasswordHPKey)pkey;
            }
            else {
                throw new CFLibUnsupportedClassException(getClass(), "setPKey", "pkey", pkey, "CFSecJpaSecUserPasswordHPKey");
            }
        }
    }

    @Override
    public CFLibDbKeyHash256 getAuditClusterId() {
        return pkey.getAuditClusterId();
    }

    @Override
    public void setAuditClusterId(CFLibDbKeyHash256 auditClusterId) {
        pkey.setAuditClusterId(auditClusterId);
    }

    @Override
    public LocalDateTime getAuditStamp() {
        return pkey.getAuditStamp();
    }

    @Override
    public void setAuditStamp(LocalDateTime auditStamp) {
        pkey.setAuditStamp(auditStamp);
    }

    @Override
    public short getAuditActionId() {
        return pkey.getAuditActionId();
    }

    @Override
    public void setAuditActionId(short auditActionId) {
        pkey.setAuditActionId(auditActionId);
    }

    @Override
    public int getRequiredRevision() {
        return pkey.getRequiredRevision();
    }

    @Override
    public void setRequiredRevision(int revision) {
        pkey.setRequiredRevision(revision);
    }

    @Override
    public CFLibDbKeyHash256 getAuditSessionId() {
        return pkey.getAuditSessionId();
    }

    @Override
    public void setAuditSessionId(CFLibDbKeyHash256 auditSessionId) {
        pkey.setAuditSessionId(auditSessionId);
    }

    @Override
    public $iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ getRequiredSecUserId() {
        return( pkey.getRequiredSecUserId() );
    }

    @Override
    public void setRequiredSecUserId( $iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ requiredSecUserId ) {
        pkey.setRequiredSecUserId( requiredSecUserId );
    }

	@Override
	public $implIJavaAtomType$ getRequiredPWSetStamp() {
		return(requiredPWSetStamp);
	}

	public void setRequiredPWSetStamp( $implIJavaAtomType$ value ) {
		if( value == null ) {
			throw new CFLibNullArgumentException( getClass(),
				"setRequiredPWSetStamp",
				1,
				"value" );
		}
		requiredPWSetStamp = value;
	}

	@Override
	public $implIJavaAtomType$ getRequiredPasswordHash() {
		return(requiredPasswordHash);
	}

	public void setRequiredPasswordHash( $implIJavaAtomType$ value ) {
		if( value == null ) {
			throw new CFLibNullArgumentException( getClass(),
				"setRequiredPasswordHash",
				1,
				"value" );
		}
		else if( value.length() > 256 ) {
			throw new CFLibArgumentOverflowException( getClass(),
				"setRequiredPasswordHash",
				1,
				"value.length()",
				value.length(),
				256 );
		}
		requiredPasswordHash = value;
	}

    @Override
    public boolean equals( Object obj ) {
        if (obj == null) {
            return( false );
        }
        else if (obj instanceof ICFSecSecUserPassword) {
            ICFSecSecUserPassword rhs = (ICFSecSecUserPassword)obj;
		if (getPKey() != null) {
			if (rhs.getPKey() != null) {
				if (!getPKey().equals(rhs.getPKey())) {
					return( false );
				}
			}
			else {
				return( false );
			}
		}
		else if (rhs.getPKey() != null) {
			return( false );
		}

			if( getRequiredPWSetStamp() != null ) {
				if( rhs.getRequiredPWSetStamp() != null ) {
					if( ! getRequiredPWSetStamp().equals( rhs.getRequiredPWSetStamp() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredPWSetStamp() != null ) {
					return( false );
				}
			}
			if( getRequiredPasswordHash() != null ) {
				if( rhs.getRequiredPasswordHash() != null ) {
					if( ! getRequiredPasswordHash().equals( rhs.getRequiredPasswordHash() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredPasswordHash() != null ) {
					return( false );
				}
			}
            return( true );
        }
        else if (obj instanceof ICFSecSecUserPasswordH) {
            ICFSecSecUserPasswordH rhs = (ICFSecSecUserPasswordH)obj;
		if (getPKey() != null) {
			if (rhs.getPKey() != null) {
				if (!getPKey().equals(rhs.getPKey())) {
					return( false );
				}
			}
			else {
				return( false );
			}
		}
		else if (rhs.getPKey() != null) {
			return( false );
		}

			if( getRequiredPWSetStamp() != null ) {
				if( rhs.getRequiredPWSetStamp() != null ) {
					if( ! getRequiredPWSetStamp().equals( rhs.getRequiredPWSetStamp() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredPWSetStamp() != null ) {
					return( false );
				}
			}
			if( getRequiredPasswordHash() != null ) {
				if( rhs.getRequiredPasswordHash() != null ) {
					if( ! getRequiredPasswordHash().equals( rhs.getRequiredPasswordHash() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredPasswordHash() != null ) {
					return( false );
				}
			}
            return( true );
        }
        else if (obj instanceof ICFSecSecUserPasswordHPKey) {
		ICFSecSecUserPasswordHPKey rhs = (ICFSecSecUserPasswordHPKey)obj;
			if( getRequiredSecUserId() != null ) {
				if( rhs.getRequiredSecUserId() != null ) {
					if( ! getRequiredSecUserId().equals( rhs.getRequiredSecUserId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecUserId() != null ) {
					return( false );
				}
			}
		return( true );
        }
        else if (obj instanceof ICFSecSecUserPasswordBySetStampIdxKey) {
            ICFSecSecUserPasswordBySetStampIdxKey rhs = (ICFSecSecUserPasswordBySetStampIdxKey)obj;
			if( getRequiredPWSetStamp() != null ) {
				if( rhs.getRequiredPWSetStamp() != null ) {
					if( ! getRequiredPWSetStamp().equals( rhs.getRequiredPWSetStamp() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredPWSetStamp() != null ) {
					return( false );
				}
			}
            return( true );
        }
        else {
			return( false );
        }
    }
    
    @Override
    public int hashCode() {
        int hashCode = pkey.hashCode();
		if( getRequiredPWSetStamp() != null ) {
			hashCode = hashCode + getRequiredPWSetStamp().hashCode();
		}
		if( getRequiredPasswordHash() != null ) {
			hashCode = hashCode + getRequiredPasswordHash().hashCode();
		}
        return( hashCode & 0x7fffffff );
    }

    @Override
    public int compareTo( Object obj ) {
        int cmp;
        if (obj == null) {
            return( 1 );
        }
        else if (obj instanceof ICFSecSecUserPassword) {
		ICFSecSecUserPassword rhs = (ICFSecSecUserPassword)obj;
		if (getPKey() != null) {
			if (rhs.getPKey() == null) {
				return( 1 );
			}
			else {
				cmp = getPKey().compareTo(rhs.getPKey());
				if (cmp != 0) {
					return( cmp );
				}
			}
		}
		else {
			if (rhs.getPKey() != null) {
				return( -1 );
			}
		}
			if (getRequiredPWSetStamp() != null) {
				if (rhs.getRequiredPWSetStamp() != null) {
					cmp = getRequiredPWSetStamp().compareTo( rhs.getRequiredPWSetStamp() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredPWSetStamp() != null) {
				return( -1 );
			}
			if (getRequiredPasswordHash() != null) {
				if (rhs.getRequiredPasswordHash() != null) {
					cmp = getRequiredPasswordHash().compareTo( rhs.getRequiredPasswordHash() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredPasswordHash() != null) {
				return( -1 );
			}
            return( 0 );
        }
        else if (obj instanceof ICFSecSecUserPasswordHPKey) {
        if (getPKey() != null) {
            return( getPKey().compareTo( obj ));
        }
        else {
            return( -1 );
        }
        }
        else if (obj instanceof ICFSecSecUserPasswordH) {
		ICFSecSecUserPasswordH rhs = (ICFSecSecUserPasswordH)obj;
		if (getPKey() != null) {
			if (rhs.getPKey() == null) {
				return( 1 );
			}
			else {
				cmp = getPKey().compareTo(rhs.getPKey());
				if (cmp != 0) {
					return( cmp );
				}
			}
		}
		else {
			if (rhs.getPKey() != null) {
				return( -1 );
			}
		}
			if (getRequiredPWSetStamp() != null) {
				if (rhs.getRequiredPWSetStamp() != null) {
					cmp = getRequiredPWSetStamp().compareTo( rhs.getRequiredPWSetStamp() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredPWSetStamp() != null) {
				return( -1 );
			}
			if (getRequiredPasswordHash() != null) {
				if (rhs.getRequiredPasswordHash() != null) {
					cmp = getRequiredPasswordHash().compareTo( rhs.getRequiredPasswordHash() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredPasswordHash() != null) {
				return( -1 );
			}
            return( 0 );
        }
        else if (obj instanceof ICFSecSecUserPasswordBySetStampIdxKey ) {
            ICFSecSecUserPasswordBySetStampIdxKey rhs = (ICFSecSecUserPasswordBySetStampIdxKey)obj;
			if (getRequiredPWSetStamp() != null) {
				if (rhs.getRequiredPWSetStamp() != null) {
					cmp = getRequiredPWSetStamp().compareTo( rhs.getRequiredPWSetStamp() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredPWSetStamp() != null) {
				return( -1 );
			}
            return( 0 );
        }
        else {
            throw new CFLibUnsupportedClassException( getClass(),
                "compareTo",
                "obj",
                obj,
                null );
        }
    }
	@Override
    public void set( ICFSecSecUserPassword src ) {
		setSecUserPassword( src );
    }

	@Override
    public void setSecUserPassword( ICFSecSecUserPassword src ) {
		setRequiredSecUserId( src.getRequiredSecUserId() );
		setRequiredPWSetStamp( src.getRequiredPWSetStamp() );
		setRequiredPasswordHash( src.getRequiredPasswordHash() );
		setRequiredRevision( src.getRequiredRevision() );
    }

	@Override
    public void set( ICFSecSecUserPasswordH src ) {
		setSecUserPassword( src );
    }

	@Override
    public void setSecUserPassword( ICFSecSecUserPasswordH src ) {
		setRequiredSecUserId( src.getRequiredSecUserId() );
		setRequiredPWSetStamp( src.getRequiredPWSetStamp() );
		setRequiredPasswordHash( src.getRequiredPasswordHash() );
		setRequiredRevision( src.getRequiredRevision() );
    }

    public String getXmlAttrFragment() {
        String ret = pkey.getXmlAttrFragment() 
			+ " RequiredRevision=\"" + Integer.toString( getRequiredRevision() ) + "\""
			+ " RequiredPWSetStamp=" + "\"" + getRequiredPWSetStamp().toString() + "\""
			+ " RequiredPasswordHash=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredPasswordHash() ) + "\"";
        return( ret );
    }

    public String toString() {
        String ret = "<CFSecJpaSecUserPasswordH" + getXmlAttrFragment() + "/>";
        return( ret );
    }
}
